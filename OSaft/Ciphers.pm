#!/usr/bin/perl
## PACKAGE {

=pod

=encoding utf8

=head1 NAME

OSaft::Ciphers - common perl module to define O-Saft ciphers

#####
# perlcritic -3 OSaft/Ciphers.pm # -verbose 10

########################  E X P E R I M E N T A L  #######################
######################  not used in O-Saft 16.09.16  #####################

=cut

# test resources with:
## /usr/bin/time --quiet -a -f "%U %S %E %P %Kk %Mk" OSaft/Ciphers.pm  names
## 0.12  0.00  0:00.12  96%  0k  6668k
## 0.11  0.00  0:00.11  98%  0k  6852k
## 0.14  0.01  0:00.16  97%  0k  7100k


#############
# RFC in OSaft/_ciphers_iana.pm abgeglichen mit https://tools.ietf.org/rfc/rfcXXXX.txt
#   d.h. keys passen zu den Konstanten
#############

# TODO: see comment at %ciphers_names

########################  E X P E R I M E N T A L  #######################

package OSaft::Ciphers;

use strict;
use warnings;
use Carp;
our @CARP_NOT = qw(OSaft::Ciphers); # TODO: funktioniert nicht

my  $VERSION      = '17.10.17';     # official verion number of tis file
my  $CIPHERS_SID  = '@(#) Ciphers.pm 1.21 17/10/18 16:22:12';
my  $STR_UNDEF    = '<<undef>>';    # defined in osaft.pm

our $VERBOSE = 0;    # >1: option --v
   # VERBOSE instead of verbose because of perlcritic

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

## no critic qw(RegularExpressions::RequireExtendedFormatting)
#  There're a lot of expressions here, it's ok to use them without /x flag.

=pod

=head1 SYNOPSIS

    OSaft::Ciphers.pm       # on command line will print help

    use OSaft::Ciphers;     # from within perl code

=head1 DESCRIPTION

Utility package for O-Saft (o-saft.pl and related tools). This package declares
and defines common L</VARIABLES> and L</METHODS> to be used in the calling tool.
It contains the primary data structure for cipher suites.

This documentaion is intended for developers. Users should read any of the help
texts for example provided by O-Saft, i.e. C<o-saft.pl --help>.

This module provides  additional functionality  to list and check the used data
structures for the cipher suites. All  L</COMMANDS> and L</OPTIONS>  are only for
this additional functionality, please read descriptions there.

=head2 Used Functions

Following functions (methods) must be defined in the calling program:

None (06/2016).

=head1 CONCEPT

The main data structure is  C<%ciphers>, which will be defined herein.
It's defined as a static hash with the cipher's ID (hex number) as the hash key
and all cipher suite data (in an array) as value for that hash key. For example
I<AES256-SHA256>:

    '0x00,0x3D' =E<gt> [qw( TLSv12 RSA  RSA  AES  256  SHA256 Y 5246 HIGH :)],

For a more detailed description, please use:

    OSaft/Ciphers.pm ciphers_description

or consult the source code directly, in particular  C<%ciphers_desc>.

The main key -aka ID- to identify a cipher suite is the identifier (hex number)
of a cipher suite as defined vy IANA. This key is also used in all other data
structures related to ciphers.

Other data, related to the cipher suite (like the cipher suite name, the cipher
suite constant) are defined in additional data structures C<%ciphers_const> and
C<%ciphers_names>.

Each cipher suite is defined as a perl array (,see above) and will be converted
to a perl hash at initialization like:

    '0x00,0x3D' =E<gt> { ssl=>"TLSv12", keyx=>"RSA", enc=>"AES", ... },

Such a hash is simpler to use. Finally a getter method (see L</METHODS>) is
provided for each value.

This approach to specify the definition, which must be done by developers, in a
simple table, which then will be converted into a hash  automatically, is based
on the consideration that the data structure  for all cipher suite  needs to be
maintained very carefully. It is the author's opinion that tabular data is more
easy to maintain than structured data.

=cut

#The decision to use an array with proper getter methods (see METHODS) rather
#than a hash is based on the consideration that the cipher suite data structure
#needs to be maintained very carefully. It's the author's opinion that tabular
#data is simpler to maintain than structured data, which requires the hash key
#for each value in each line.

=pod

=head2 Variables

All variables except C<@cipher_results> are constants, and hence read-only. There
is no need to change them in the calling program.

=head2 Methods

Because all variables are constants, we only provide getter methods for them.

=head2 Testing

All data structures are defined herein. For testing, the data structures can be
read from a file.

=head2 Documentaion

This documentaion describes the public variables and methods only,  but not the
internal ones, in particular the  C<print*()> functions.  Please see the source
itself for that.

=head1 VARIABLES

=over 4

=item %ciphers

Hash with all cipher suites and paramters of each suite. Indexed by cipher ID.

=item %ciphers_desc

Describes the data structure in C<%ciphers>.

=item %ciphers_names

Hash with various names, identifiers and constants for each cipher suite.
Indexed by cipher ID.

=item %ciphers_alias

Hash with additional names, identifiers and constants for a cipher suite.
Indexed by cipher ID.

=item @cipher_results

Array with all checked ciphers.

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
                %ciphers
                %ciphers_desc
                %ciphers_names
                %ciphers_alias
                %ciphers_const
                @cipher_results
                get_param
                get_ssl
                get_keyx
                get_auth
                get_enc
                get_bits
                get_mac
                get_dtls
                get_rfc
                get_sec
                get_tags
                get_score
                get_desc
                get_hex
                get_name
                get_alias
                get_const
                sort_cipher_names
                cipher_done
);
# insert above in vi with:
# :r !sed -ne 's/^our \([\%$@][a-zA-Z0-9_][^ (]*\).*/\t\t\1/p' %
# :r !sed -ne 's/^sub \([a-zA-Z][^ (]*\).*/\t\t\1/p' %

# TODO: interanl wrappers for main's methods
sub _trace      { ::_trace(@_); return; }   ## no critic qw(Subroutines::RequireArgUnpacking)
sub _trace0     { ::_trace(@_); return; }   ## no critic qw(Subroutines::RequireArgUnpacking)
sub _trace1     { ::_trace(@_); return; }   ## no critic qw(Subroutines::RequireArgUnpacking)
sub _trace2     { ::_trace(@_); return; }   ## no critic qw(Subroutines::RequireArgUnpacking)
sub _trace3     { ::_trace(@_); return; }   ## no critic qw(Subroutines::RequireArgUnpacking)

sub _warn       { my @args = @_; carp("**WARNING: ", join(" ", @args)); return; }
sub vprint      { my @args = @_; return if ($VERBOSE<1); print("# ", join(" ", @args) . "\n");  return; }
sub v2print     { my @args = @_; return if ($VERBOSE<2); print("# ", join(" ", @args) . "\n");  return; }

#_____________________________________________________________________________
#________________________________________________________________ variables __|

our %ciphers_desc = (   # description of following %ciphers table
    'head'          => [qw( ssl  keyx auth enc  bits mac  dtls rfc  sec  tags )],
                            # abbreviations used by openssl:
                            # SSLv2, SSLv3, TLSv1, TLSv1.1, TLSv1.2
                            # Kx=  key exchange (DH is diffie-hellman)
                            # Au=  authentication
                            # Enc= encryption with bit size
                            # Mac= mac encryption algorithm
    'text'          => [ # full description of each column in 'ciphers' below
                            # all following informations as reported by openssl 0.9.8 .. 1.0.1h
        'SSL/TLS version',  # Protocol Version:
                            # SSLv2, SSLv3, TLSv1, TLSv11, TLSv12, TLSv13, DTLS0.9, DTLS1.0, PCT
                            # NOTE: all SSLv3 are also TLSv1, TLSv11, TLSv12
                            # (cross-checked with sslaudit.ini)
        'Key Exchange',     # DH, ECDH, ECDH/ECDSA, RSA, KRB5, PSK, SRP, GOST
                            # last column is a : separated list (only export from openssl)
                            # different versions of openssl report  ECDH or ECDH/ECDSA
        'Authentication',   # None, DSS, RSA, ECDH, ECDSA, KRB5, PSK, GOST01, GOST94
        'Encryption Algorithm', # None, AES, AESCCM, AESGCM, CAMELLIA, DES, 3DES, FZA, IDEA, RC4, RC2, SEED, GOST89
        'Key Size',         # in bits
        'MAC Algorithm',    # MD5, SHA1, SHA256, SHA384, AEAD, GOST89, GOST94
        'DTLS OK',          # Y  if cipher is compatible for DTLS, N  otherwise
                            # (information from IANA)
        'RFC',              # RFC number where cipher was defined
        'Security',         # LOW, MEDIUM, HIGH as reported by openssl 0.9.8 .. 1.0.1h
                            # WEAK as reported by openssl 0.9.8 as EXPORT
                            # weak unqualified by openssl or know vulnerable
                            # NOTE: weak includes NONE (no security at all)
                            # high unqualified by openssl, but considerd secure
                            #
        'tags',             # export  as reported by openssl 0.9.8 .. 1.0.1h
                            # OSX     on Mac OS X only
                            # :    (colon) is empty marker (need for other tools
        ],
    'sample'        => { # example
        '0x00,0x3D' => [qw( TLSv12 RSA  RSA  AES  256  SHA256 Y 5246 HIGH :)], # AES256-SHA256
        },
); # %ciphers_desc

####### nur  %ciphers  und  %ciphers_names  wird verwendet
####### alle anderen  %_cipher*  sind nur zur Initialisierung

our %ciphers = (
    #? list of all ciphers, will be generated in _ciphers_init()
    #------------------+----+----+----+----+----+----+-------+----+---+-------,
    # hex,hex   => [qw( ssl  keyx auth enc  bits mac  DTLS-OK RFC  sec tags )],
    #------------------+----+----+----+----+----+----+-------+----+---+-------,
    #------------------+----+----+----+----+----+----+-------+----+---+-------,
# ...
); # %ciphers

    # iana	- aus _ciphers_iana.pm
    # OpenSSL	- aus _ciphers_??   (ssl.h, tls.h, ...)
    # openssl	- aus _ciphers_openssl_all.pm  (openssl ciphers -V)
    # osaft	- aus _ciphers_osaft.pm  (handgestrickt)

our %ciphers_const = (
    #? list of cipher suite constant names, will be generated in _ciphers_init()
    #------------------+-------+-------+-------+--------,
    # hex,hex   => [qw( iana    OpenSSL openssl osaft )],
    #                             (osaft: SSL_CK_ and TLS_ prefix missing)
    #------------------+-------+-------+-------+--------,
# ...
); # %ciphers_const
#  defined in OSaft/_ciphers_iana.pm, OSaft/_ciphers_osaft.pm

our %ciphers_names = (
    #? list of cipher suite names, will be generated in _ciphers_init()
    #------------------+-------+-------+-------+--------,
    # hex,hex   => [qw( iana    OpenSSL openssl osaft )],
    #                             (osaft: SSL_CK_ and TLS_ prefix missing)
    #------------------+-------+-------+-------+--------,
# ...
); # %ciphers_names
#  defined in OSaft/_ciphers_iana.pm, OSaft/_ciphers_osaft.pm

our %ciphers_alias = (
    #? list of cipher suite alias names, will be generated in _ciphers_init()
    #------------------+-----------------------------+----------------------,
    # hex,hex   => [qw( cipher suite name aliases )],# comment (where found)
    #------------------+-----------------------------+----------------------,
# ...
); # %ciphers_alias
#  defined in OSaft/_ciphers_osaft.pm

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
#______________________________________________________ temporary variables __|

###
### die Hashes werden hier statisch definiert, können aber dynamisch
### aus den Files geladen werden
### Stand 6/2016:  bis die erste statische Version fertig ist, werden die
### Daten dynamisch geladen

my %_ciphers_openssl_all = (
    #? internal list, generated by gen_ciphers.sh
    #-------------------+----+----+----+----+----+----+----+-------,
    # hex,hex    => [qw( ssl  keyx auth enc  bits mac  name tags )],
    #-------------------+----+----+----+----+----+----+----+-------,
#   '0x00,0x05'  => [qw( SSLv3 RSA RSA  RC4   128 SHA1 RC4-SHA
    #-------------------+----+----+----+----+----+----+----+-------,
); # %_ciphers_openssl_all
eval {require qw{OSaft/_ciphers_openssl_all.pm}; } or _warn "cannot read OSaft/_ciphers_openssl_all.pm";

my %_ciphers_openssl_inc = (
    #? internal list, generated from openssl source
); # %_ciphers_openssl_inc

my %_ciphers_iana = (
    #? internal list, generated by gen_ciphers.sh
    #-------------------+------------------------------------+-------+---------,
    # hex,hex    => [qw( IANA cipher suite constant           RFC(s) DTLS-OK )],
    #-------------------+------------------------------------+-------+---------,
#   '0xC0,0x32'  => [qw( TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 5289    Y      )],
#   '0xC0,0x33'  => [qw( TLS_ECDHE_PSK_WITH_RC4_128_SHA       5489,6347    N )],
    #-------------------+------------------------------------+-------+---------,
); # %__ciphers_iana
eval {require qw{OSaft/_ciphers_iana.pm}; } or _warn "cannot read OSaft/_ciphers_iana.pm";

my %_ciphers_osaft = (
    #? internal list, additions to %_ciphers_openssl
    # /opt/tools/openssl-chacha/bin/openssl ciphers -V ALL:eNULL:LOW:EXP \
);# %_ciphers_osaft
eval {require qw{OSaft/_ciphers_osaft.pm}; } or _warn "cannot read OSaft/_ciphers_osaft.pm";

######################################################
sub id2key      {
    #? convert any hex or integer id to key used in internal data structure
# Umrechnung:  0x0300C01C <--> 0xC0C1 <--> 0xC0,0x1C
    my $ssl_base    = 0x02000000;   #   33554432
    my $tls_base    = 0x03000000;   #   50331648
    my $ptc_base    = 0x80000000;   # 2147483648
    my $chacha_mask = 0xCC;         # i.e 0xCC,0xAA
    my $fips_mask   = 0xFE;         # i.e 0xFE,0xE0
    my $gost_mask   = 0xFF;         # i.e 0xFF,0x01
		# Sonderfall 0x00,0x1e  , sonst alle upper case
    return;
}; # id2key

# sub is_auth   { }
# sub is_enc    { }
# sub is_ephermeral { }
# sub is_export { }

######################################################

#_____________________________________________________________________________
#__________________________________________________________________ methods __|

=pod

=head2 get_param($cipher, $key)

=head2 get_ssl( $cipher)

=head2 get_keyx($cipher)

=head2 get_auth($cipher)

=head2 get_enc( $cipher)

=head2 get_bits($cipher)

=head2 get_mac( $cipher)

=head2 get_dtls($cipher)

=head2 get_rfc( $cipher)

=head2 get_sec( $cipher)

=head2 get_tags($cipher)

=head2 get_score($cipher)

=head2 get_hex(  $cipher)

=head2 get_name( $cipher)

=head2 get_alias($cipher)

=head2 get_const($cipher)

=head2 get_desc( $cipher)

Get information from internal C<%cipher> data structure.

=cut

# some people prefer to use a getter function to get data from objects
# each function returns a spcific value (column) from the %cipher table
# see %ciphers_desc about description of the columns
# returns STR_UNDEF if requested cipher is missing
sub get_param   {
    #? internal method to return required value from %cipher
    my ($cipher, $key) = @_;
    return $ciphers{$cipher}->{$key} || '' if ((grep{/^$cipher/i} %ciphers)>0);
    return $STR_UNDEF;
}; # get_param
sub get_ssl     { my $c=shift; return get_param($c, 'ssl');  }
sub get_keyx    { my $c=shift; return get_param($c, 'keyx'); }
sub get_auth    { my $c=shift; return get_param($c, 'auth'); }
sub get_enc     { my $c=shift; return get_param($c, 'enc');  }
sub get_bits    { my $c=shift; return get_param($c, 'bits'); }
sub get_mac     { my $c=shift; return get_param($c, 'mac');  }
sub get_dtls    { my $c=shift; return get_param($c, 'dtls'); }
sub get_rfc     { my $c=shift; return get_param($c, 'rfc');  }
sub get_sec     { my $c=shift; return get_param($c, 'sec');  }
sub get_tags    { my $c=shift; return get_param($c, 'tags'); }
sub get_score   { my $c=shift; return $STR_UNDEF; } # obsolete since 16.06.16

sub get_desc    {
    # get description for specified cipher from %ciphers
    my $c=shift;
    if (! defined $ciphers{$c}) {
       _warn("undefined cipher description for '$c'"); # TODO: correct %ciphers
       return $STR_UNDEF;
    }
    my @x = sort values %{$ciphers{$c}};
    shift @x;
    return join(" ", @x) if ((grep{/^$c/} %ciphers)>0);
    return '';
}

=pod

=head2 get_hex($cipher)

Get cipher's hex key from C<%ciphers_names> or C<%ciphers_alias> data structure.

=head2 get_name($cipher)

Check if given C<%cipher> name is a known cipher.

=cut

sub get_hex     {
    #? find hex key for cipher in %ciphers_names or %ciphers_alias
    #  example: RC4-MD5 -> 0x01,0x00,0x80 ;  AES128-SHA256 -> 0x00,0x3C
    my $c = shift;
# FIXME: returns first matching even if more exist; example: RC4-MD5
    foreach my $k (keys %ciphers_names) { # database up to VERSION 14.07.14
        return $k if (($ciphers_names{$k}[0] eq $c) or ($ciphers_names{$k}[1] eq $c));
    }
    foreach my $k (keys %ciphers_alias) { # not yet found, check for alias
        return $k if ($ciphers_alias{$k}[0] eq $c);
    }
    # NOTE: need to check if this is necessary here
    #foreach my $k (keys %ciphers_old) {   # not yet found, check old names
    #    return $k if ($ciphers_old{$k}[0] eq $c);
    #}
    return '';
} # get_hex


sub get_key     {
    #? translate given string to valid hex key for %cipher; returns key if exists
    #  example: RC4-MD5 -> 0x01,0x00,0x80 ;  AES128-SHA256 -> 0x00,0x3C
    my $txt = shift;
    my $key = uc($txt);
       $key =~ s/X/x/g;
# FIXME: returns first matching even if more exist; example: RC4-MD5
    return $key if defined $ciphers{$key};
    $key =  $txt;
    $key =~ s/^(?:SSL[23]?|TLS1?)_//;   # strip any prefix;
    $key =~ s/^(?:CK|TXT)_//;     # strip any prefix;
    # not a key itself, try to find in names
    foreach my $k (keys %ciphers_names) {
        foreach (qw( iana OpenSSL openssl osaft )) {
print "#$ciphers_names{$k}->{$_}#\n" if ($ciphers_names{$k}->{$_} =~ m/$key/i);
            return $k if (defined $ciphers_names{$k}->{$_} && ($ciphers_names{$k}->{$_} =~ m/^$key$/i));
        }
    }
    return "";
} # get_key

sub get_name    {
    #? check if given cipher name is a known cipher
    #  checks in %ciphers if nof found in %ciphers_names
    #  example: RC4_128_WITH_MD5 -> RC4-MD5 ;  RSA_WITH_AES_128_SHA256 -> AES128-SHA256
    # Note: duplicate name (like RC4_128_WITH_MD5) are no problem, because they
    #       use the same cipher suite name (like RC4-MD5).
    my $cipher  = shift;
    return $cipher if ((grep{/^$cipher/} %ciphers)>0);
    _trace("get_name: search $cipher");
    foreach my $k (keys %ciphers_names) {
        return $ciphers_names{$k}[0] if ($cipher =~ m/$ciphers_names{$k}[0]/);
        return $ciphers_names{$k}[0] if ($ciphers_names{$k}[1] =~ /$cipher/);
    }
    # nothing found yet, try more lazy match
    foreach my $k (keys %ciphers_names) {
        if ($ciphers_names{$k}[0] =~ m/$cipher/) {
            _warn("partial match for cipher name found '$cipher'");
            return $ciphers_names{$k}[0];
        }
    }
    return '';
} # get_name

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
    # known insecure (i.e. CBC, DES, RC4) and NULL ciphers are added at the end
    my @ciphers = @_;
    my @sorted  ;
    my @latest  ;
    my $cnt     = scalar @ciphers;  # number of passed ciphers; see check at end

    # now define list of regex to match openssl cipher suite names
    # each regex could be seen as a  class of ciphers with the same strength
    # the list defines the strength in descending order, most strength first
    # NOTE the list may contain pattern, which actually do not match a valid
    # cipher suite name; doese't matter, but may avoid future adaptions, see
    # warning at nd also

    my @insecure = (
        qw((?:RC[24]))  ,               # all RC2 and RC4
        qw((?:CBC|DES)) ,               # all CBC, DES, 3DES
        qw((?:DSS))     ,               # all DSS
        qw((?:MD[2345])),               # all MD
        qw(DH.?(?i:anon)) ,             # Anon needs to be caseless
        qw((?:NULL))    ,               # all NULL
    );
    my @strength = (
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
        qw(ECDH[_-].*?CHACHA)   ,       # 5. all remaining ecliptical curve
        qw(ECDH[_-].*?512) ,
        qw(ECDH[_-].*?384) ,
        qw(ECDH[_-].*?256) ,
        qw(ECDH[_-].*?128) ,
        qw(AES) ,                       # 5. all AES and specials
        qw(KRB5) ,
        qw(SRP) ,
        qw(PSK) ,
        qw(GOST) ,
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
        #_trace2("sort_cipher_names(): regex\t= $rex }");
        push(@sorted, grep{ /$rex/} @ciphers);  # add matches to result
        @ciphers    = grep{!/$rex/} @ciphers;   # remove matches from original list
    }
    push(@sorted, @latest);                     # add insecure ciphers again
    my $num = scalar @sorted;
    if ($cnt != $num) {
        # print warning if above algorithm misses ciphers; uses perl's  warn()
        # instead of our _warn() to clearly inform the user that the code here
        # needs to be fixed
        #warn STR_WARN . "missing ciphers in sorted list: $num < $cnt";
        warn "**WARNING: missing ciphers in sorted list: $num < $cnt";
        #dbx# print "## ".@sorted . " # @ciphers";
    }
    return @sorted;
} # sort_cipher_names

#_____________________________________________________________________________
#_________________________________________________________ internal methods __|

sub show_getter03 {
    #? show hardcoded example for all getter functions for key 0x00,0x03

#   0x00,0x03	RSA  40   N    RC4  RSA(512) MD5  4346,6347  0    WEAK SSLv3  export
#   0x00,0x03   EXP-RC4-MD5    RSA_RC4_40_MD5
# C,0x00,0x03   RSA_EXPORT_WITH_RC4_40_MD5

    my $cipher = "0x00,0x03";
    print "# testing: $cipher ...\n";
    printf("# %20s\t%s\t%-14s\t# %s\n", "function(key)", "key", "value", "(expected)");
    printf("#----------------------+-------+----------------+---------------\n");
#   printf("%-8s %s\t%s\t%-14s\t# %s\n", "get_hex",  $cipher, "hex",  get_hex($cipher),  "?");
    printf("%-8s %s\t%s\t%-14s\t# %s\n", "get_dtls", $cipher, "dtls", get_dtls($cipher), "N");
    printf("%-8s %s\t%s\t%-14s\t# %s\n", "get_bits", $cipher, "bits", get_bits($cipher), "40");
    printf("%-8s %s\t%s\t%-14s\t# %s\n", "get_enc",  $cipher, "enc",  get_enc( $cipher), "RC4");
    printf("%-8s %s\t%s\t%-14s\t# %s\n", "get_keyx", $cipher, "keyx", get_keyx($cipher), "RSA(512)");
    printf("%-8s %s\t%s\t%-14s\t# %s\n", "get_auth", $cipher, "auth", get_auth($cipher), "RSA");
    printf("%-8s %s\t%s\t%-14s\t# %s\n", "get_mac",  $cipher, "mac",  get_mac( $cipher), "MD5");
    printf("%-8s %s\t%s\t%-14s\t# %s\n", "get_rfc",  $cipher, "rfc",  get_rfc( $cipher), "4346,6347");
    printf("%-8s %s\t%s\t%-14s\t# %s\n", "get_sec",  $cipher, "sec",  get_sec( $cipher), "WEAK");
    printf("%-8s %s\t%s\t%-14s\t# %s\n", "get_ssl",  $cipher, "ssl",  get_ssl( $cipher), "SSLv3");
    printf("%-8s %s\t%s\t%-14s\t# %s\n", "get_tags", $cipher, "tags", get_tags($cipher), "export");
    printf("%-8s %s\t%s\t%-14s\t# %s\n", "get_name", $cipher, "name", get_name($cipher), "?");
    printf("%-8s %s\t%s\t%-14s\t# %s\n", "get_desc", $cipher, "desc", get_desc($cipher), "40 4346,6347 MD5 N RC4 RSA RSA(512) SSLv3 WEAK export");
    printf("#----------------------+-------+----------------+---------------\n");
    return;
} # show_getter03

sub show_getter {
    #? show example for all getter functions
    my $cipher = shift;
    printf("#%s:\n", (caller(0))[3]);
    if ($cipher !~ m/^[x0-9a-fA-F,]+$/) {   # no cipher given, print hardcoded example
        show_getter03;
        return;
    }
    print "# testing: $cipher ...\n";
    printf("# %20s\t%s\t%s\n", "function(key)", "key", "value");
    printf("#----------------------+-------+----------------\n");
#   printf("%-8s %s\t%s\t%s\n", "get_hex",  $cipher, "hex",  get_hex($cipher)  );
    printf("%-8s %s\t%s\t%s\n", "get_dtls", $cipher, "dtls", get_dtls($cipher) );
    printf("%-8s %s\t%s\t%s\n", "get_bits", $cipher, "bits", get_bits($cipher) );
    printf("%-8s %s\t%s\t%s\n", "get_enc",  $cipher, "enc",  get_enc( $cipher) );
    printf("%-8s %s\t%s\t%s\n", "get_keyx", $cipher, "keyx", get_keyx($cipher) );
    printf("%-8s %s\t%s\t%s\n", "get_auth", $cipher, "auth", get_auth($cipher) );
    printf("%-8s %s\t%s\t%s\n", "get_mac",  $cipher, "mac",  get_mac( $cipher) );
    printf("%-8s %s\t%s\t%s\n", "get_rfc",  $cipher, "rfc",  get_rfc( $cipher) );
    printf("%-8s %s\t%s\t%s\n", "get_sec",  $cipher, "sec",  get_sec( $cipher) );
    printf("%-8s %s\t%s\t%s\n", "get_ssl",  $cipher, "ssl",  get_ssl( $cipher) );
    printf("%-8s %s\t%s\t%s\n", "get_tags", $cipher, "tags", get_tags($cipher) );
    printf("%-8s %s\t%s\t%s\n", "get_name", $cipher, "name", get_name($cipher) );
    printf("%-8s %s\t%s\t%s\n", "get_desc", $cipher, "desc", get_desc($cipher) );
    printf("#----------------------+-------+----------------\n");
    return;
} # show_getter

sub show_key    {
    #? print hex key if found in internal data structure
    my $txt = shift;
    my $key = get_key($txt);
    printf("#%s:\n", (caller(0))[3]);
    print "key for $txt : $key\n";
    return;
} # show_key

sub show_desc   {
    #? print textual description for columns %cipher hash

    printf("#%s:\n", (caller(0))[3]);
    print  "\n# %ciphers : example line:\n";
    my $key = 0;
    printf("  '0x00,0x3D' -> [");
    foreach (@{$ciphers_desc{head}}) {
        printf("\t%s", $ciphers_desc{sample}->{'0x00,0x3D'}[$key]);
        $key++;
    }
    printf(" ]\n");
    print  "\n# %ciphers : tabular description of one (example) line:\n";
    printf("#-------+------+-----------------------+--------\n");
    printf("# [%s]\t%5s\t%16s\t%s\n", "nr", "key", "description", "example");
    printf("#-------+------+-----------------------+--------\n");
    $key = 0;
    foreach (@{$ciphers_desc{head}}) {
        printf("  [%s]\t%6s\t%-20s\t%s\n", $key, $ciphers_desc{head}[$key],
            $ciphers_desc{text}[$key], $ciphers_desc{sample}->{'0x00,0x3D'}[$key]);
        $key++;
    }
    printf("#-------+------+-----------------------+--------\n");

    print  "\n# %ciphers : description of one line as perl code:\n";
    printf("# varname  %-23s\t# example # description\n", "%ciphers hash");
    printf("#---------+-----------------------------+---------+---------------\n");
    $key = 0;
    foreach (@{$ciphers_desc{head}}) {
        printf("  %6s = \$ciphers{'0xBE,0xEF'}[%s];\t# %-7s # %s\n",
            '$' . $ciphers_desc{head}[$key], $key,
            $ciphers_desc{sample}->{'0x00,0x3D'}[$key], $ciphers_desc{text}[$key]);
        $key++;
    }
    printf("#---------+-----------------------------+---------+---------------\n");

    print  "\n# %ciphers_names : description of one line as perl code:\n";
    #printf("# key     => [qw( iana OpenSSL openssl osaft )],\n)";
    printf("# varname  %-31s\t  # source of name\n", "%ciphers hash");
    printf("#---------+---------------------------------------+-----------------\n");
    $key = 0;
    foreach (qw( iana OpenSSL openssl osaft )) {
        printf("%8s = \$ciphers_names{'0xBE,0xEF'}[%s];\t  # %s\n", '$' .  $_,
            $key, $_);
        $key++;
    }
    printf("#---------+---------------------------------------+-----------------\n");

    print  "\n# %ciphers_const : description of one line as perl code:\n";
    #printf("# key     => [qw( iana OpenSSL openssl osaft )],\n)";
    printf("# varname  %-31s\t  # source of constant\n", "%ciphers hash");
    printf("#---------+---------------------------------------+-----------------\n");
    $key = 0;
    foreach (qw( iana OpenSSL openssl osaft )) {
        printf("%8s = \$ciphers_const{'0xBE,0xEF'}[%s];\t  # %s\n", '$' .  $_,
            $key, $_);
        $key++;
    }
    printf("#---------+---------------------------------------+-----------------\n");

    print  "\n# \@cipher_results : description of one line in array:\n";
# currently (12/2015)
    printf("#------+---------------+-------\n");
    printf("# %s\t%12s\t%s\n", "ssl", "cipher name", "support");
    printf("#------+---------------+-------\n");
    printf(" %s\t%-12s\t%s\n", "TLSv12", "AES256-SHA256", "yes");
    printf(" %s\t%-12s\t%s\n", "SSLv3", "NULL", "no");
    printf("#------+---------------+-------\n");

    printf("# in future (01/2016)\n");
    printf("#------+---------------+-------+-------+-------+-------+-------\n");
    printf("# %s\t%s\t%s\t%s\t%s\t%s\t%s\n",
        "ssl", "cipher\t", "pos +cipher", "pos +cipherraw", "dh-bits", "dh-par", "comment");
    printf("#------+---------------+-------+-------+-------+-------+-------\n");
    printf(" %s\t%s\t%s\t%s\t%s\t%s\t%s\n",
        "TLSv12", "0x00,0x3D", "0", "3", "512", "ec256", "comment");
    printf("#------+---------------+-------+-------+-------+-------+-------\n");

    return;
} # show_desc

sub show_overview   {
    printf("#%s:\n", (caller(0))[3]);
    print  <<'EoT';
= overview if cipher description and name exists in internal data structure
=   description of columns:
=       key         - hex key for cipher suite
=       cipher desc - cipher suite known in internal data structure
=       cipher const- cipher suite constant name exists
=       cipher name - cipher suite (openssl) name exists
=       name # desc - 'yes' if name and description exists

EoT
    print  "= Note: following columns should have a *\n";
    print  "=       ciphers_desc, ciphers_const, ciphers_name\n";
    printf("=%s+%s+%s+%s+%s\n", "-" x 14, "-" x 7, "-" x 7, "-" x 7, "-" x 7, "-" x 7);
    printf("= %13s\t%s\t%s\t%s\t%s\t%s\n",  "",  "ciphers", "ciphers", "ciphers", "ciphers", "name +");
    printf("= %13s\t%s\t%s\t%s\t%s\t%s\n", "key ", " desc", " const",   " name",   " alias",  " desc");
    printf("=%s+%s+%s+%s+%s+%s\n", "-" x 14, "-" x 7, "-" x 7, "-" x 7, "-" x 7, "-" x 7);
    my $cnt = 0;
    foreach my $key (sort keys %ciphers) {
         $cnt++;
         my $both  = "no";
         my $desc  = " ";
         my $name  = " ";
         my $const = " ";
         my $alias = " ";
         $desc  = "*" if $ciphers{$key};
         $name  = "*" if $ciphers_names{$key}->{'osaft'};
         $const = "*" if defined $ciphers_const{$key};
         $alias = "*" if defined $ciphers_alias{$key};
         $both  = "yes" if ($desc eq "*" and $name eq "*");
         printf("%14s\t%s\t%s\t%s\t%s\t%s\n", $key, $desc, $const, $name, $alias, $both);
    }
    printf("=%s+%s+%s+%s+%s+%s\n", "-" x 14, "-" x 7, "-" x 7, "-" x 7, "-" x 7, "-" x 7);
    printf("= %s ciphers\n", $cnt);
    return;
}; # show_overview

sub show_const  {
    printf("#%s:\n", (caller(0))[3]);
    print  <<'EoT';
= overview of various cipher suite constant names
=   description of columns:
=       key         - hex key for cipher suite
=       iana        - constant of cipher suite as defined by IANA
=       OpenSSL     - constant of cipher suite used in openssl's *.h files
=       osaft       - constant of cipher suite used by O-Saft
=       o=iana o=op - yes if IANA's cipher suite name is same as O-Saft's name

EoT
    printf("=%s+%s+%s+%s+%s-%s\n", "-" x 14, "-" x 39, "-" x 31, "-" x 31, "-" x 7, "-" x 7);
    printf("=%s   osaft = \n", " " x 119);
    printf("= %13s\t\t%-37s\t%-31s\t%-23s\t%s\n", "key ", "iana", "OpenSSL", "osaft", "iana\topenssl");
    printf("=%s+%s+%s+%s+%s+%s\n", "-" x 14, "-" x 39, "-" x 31, "-" x 31, "-" x 7, "-" x 7);
    foreach my $key (sort keys %ciphers) {
         my $const1 = $ciphers_const{$key}->{'iana'}    || "";
         my $const2 = $ciphers_const{$key}->{'OpenSSL'} || "";
         my $const3 = $ciphers_const{$key}->{'osaft'}   || "";
         my $o_i = "no";
            $o_i = "yes" if ($const1 eq ("TLS_" . $const3));
         my $o_o = "no";
            $o_o = "yes" if ($const2 eq ("TLS_" . $const3));
         printf("%14s\t%-37s\t%-31s\t%-31s\t%s\t%s\n", $key, $const1, $const2, $const3, $o_i, $o_o);
    }
    printf("=%s+%s+%s+%s+%s+%s\n", "-" x 14, "-" x 39, "-" x 31, "-" x 31, "-" x 7, "-" x 7);
    return;
}; # show_const

sub show_names  {
    printf("#%s:\n", (caller(0))[3]);
    print  <<'EoT';
= overview of various cipher suite names
=   description of columns:
=       key         - hex key for cipher suite
=       OpenSSL     - cipher suite name used in openssl's *.h files
=       openssl     - cipher suite name used by openssl executable
=       osaft       - cipher suite name used by O-Saft
=       o=o         - yes if openssl's cipher suite name is same as O-Saft's name

EoT

    printf("=%s+%s+%s+%s+%s\n", "-" x 14, "-" x 23, "-" x 23, "-" x 23, "-" x 7);
    printf("= %13s\t\t%-23s\t%-23s\t%-15s\t%s\n", "key ", "OpenSSL", "openssl", "osaft", "openssl=osaft");
    printf("=%s+%s+%s+%s+%s\n", "-" x 14, "-" x 23, "-" x 23, "-" x 23, "-" x 7);
    foreach my $key (sort keys %ciphers) {
         my $name1 = $ciphers_names{$key}->{'openssl'} || "";
         my $name2 = $ciphers_names{$key}->{'osaft'}   || "";
         my $both  = "no";
            $both  = "yes" if ($name1 eq $name2);
         printf("%14s\t%-23s\t%-23s\t%-23s\t%s\n", $key,
                $ciphers_names{$key}->{'OpenSSL'} || "",
                $name1, $name2, $both,
               );
    }
    printf("=%s+%s+%s+%s+%s\n", "-" x 14, "-" x 23, "-" x 23, "-" x 23, "-" x 7);
    return;
}; # show_names

######################################################
# show_names_o-o {
#   print  "=    openssl O-Saft iden-";
#   print  "= key  name  name   tical";
#   print  "=----+------+----+-------";
#   print  "  key DHE-   DHE-   yes  ";
#   print  "  key DHE-   EDH-   no   ";
# }; #

# show_const_o-o {
#   print  "=    openssl O-Saft iden-";
#   print  "= key const  const  tical";
#   print  "=----+------+----+-------";
#   print  "  key TLS_   TLS_   yes  ";
#   print  "  key TLS_   PCT_   no   ";
# }; #
######################################################

sub show_rfc    {
    printf("#%s:\n", (caller(0))[3]);
    print  <<'EoT';
= cipher suite and corresponding RFCs
=   description of columns:
=       key         - hex key for cipher suite
=       RFC         - RFC numbers, where cipher suite is described
=       OpenSSL     - cipher suite name as used in openssl

EoT
    printf("=%s+%s+%s\n", "-" x 14, "-" x 15, "-" x 23);
    printf("= %13s\t\t%s\t%s\n", "key ", "RFC", "OpenSSL");
    printf("=%s+%s+%s\n", "-" x 14, "-" x 15, "-" x 23);
    foreach my $key (sort keys %ciphers) {
         my $rfc = $ciphers{$key}->{'rfc'} || "";
            $rfc = "$rfc" if ($rfc ne "");
         printf("%14s\t%-15s\t%-23s\n", $key,
                $rfc,
                $ciphers_names{$key}->{'osaft'} || "",
               );
         # TODO: in 'rfc' können mehrer stehen, durch Komma getrennt
    }
    printf("=%s+%s+%s\n", "-" x 14, "-" x 15, "-" x 23);
    return;
}; # show_rfc


sub _show_tablehead {
    # print table headline according given format
    my $format = shift;
    my @values;

    return if ($format =~ m/tab$/);

    if ($format =~ m/^(?:dump|yeast)/) {
        my $key = "0x00,0x00";  # use first entry to get keys
        foreach my $val (sort keys %{$ciphers{$key}}) {
            push(@values, $val);
        }
        printf"%12s\t%s\n", $key, join("\t",@values);
        printf"#%s%s\n", "-" x 14, join("", ("+-------" x ($#values + 1)));
    }
#   printf("=%14s\t%-39s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
#            "key", "name", "sec", "ssl", "enc", "bit", "mac", "auth", "keyx", "score", "tag" );
#	format=15.12

    if ($format =~ m/^(?:16|16.06.16|new|osaft)/) {
        printf("=%14s\t%-47s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
               "key", "name", "ssl", "keyx", "auth", "enc", "bits", "mac", "tags" );
        printf("=%s+%s+%s+%s+%s+%s+%s+%s+%s\n",
               "-" x 14, "-" x 47, "-" x 7, "-" x 7, "-" x 7, "-" x 7, "-" x 7, "-" x 7, "-" x 11 );
    }

#    0x00,0x00,0x00 - NULL-MD5                SSLv2 Kx=RSA(512) Au=RSA  Enc=None(0) Ma
    if ($format =~ m/^openssl/) {
        printf("=% 18s - %-23s %-5s %-11s %-7s %-11s %-7s %s\n",
               "key", "name", "ssl", "keyx", "auth", "enc(bit)", "mac", "tags" );
        printf("=%s+%s+%s+%s+%s+%s+%s+%s\n",
               "-" x 19, "-" x 24, "-" x 5, "-" x 11, "-" x 7, "-" x 11, "-" x 7, "-" x 11 );
    }

    return;
} # _show_tablehead

sub _show_tableline {
    # print table headline according given format
    my $format = shift;
    return;
} # _show_tableline

# =pod
#
# =head2 show_ciphers($format)
#
# Print C<%ciphers> data structure in specified format.
#
# Supported formats are:
# * openssl       - like openssl ciphers -V
# * osaft         - most important data
# * dump          - all available data
# * 15.12.15      - format like in version 15.12.15 (for compatibility)
#
# =cut

sub show_ciphers    {
    #? print internal list of ciphers in specified format
    my $format = shift;
    printf("#%s:\n", (caller(0))[3]);

    if ($format !~ m/(?:dump(?:tab)|yeast|osaft|openssl|15.12.15|15|old|16.06.16|16|new)/) {
        printf("**WARNING: unknown format '%s'", $format);
        return;
    }

    if ($format !~ m/tab$/) {
        print  <<'EoT';
= internal lists of ciphers
=   description of columns:
=       key         - hex key for cipher suite

EoT
        my $key = 0;
        foreach (@{$ciphers_desc{head}}) {
            printf("=       %-4s        - %s\n", $ciphers_desc{head}[$key],
                $ciphers_desc{text}[$key]);
            $key++;
        }
    }

    _show_tablehead($format);

    foreach my $key (sort keys %ciphers) {

        my @values;
        if ($format =~ m/^(?:dump|yeast)/) {
            foreach my $val (sort keys %{$ciphers{$key}}) {
                push(@values, $ciphers{$key}->{$val});
            }
            printf"%12s\t%s\n", $key, join("\t",@values); next;
        }

        my $name= $ciphers_names{$key}->{'iana'} || '';
        my $ssl = $ciphers{$key}->{'ssl'}   || '';
        my $kx  = $ciphers{$key}->{'keyx'}  || '';
        my $au  = $ciphers{$key}->{'auth'}  || '';
        my $enc = $ciphers{$key}->{'enc'}   || '';
        my $bit = $ciphers{$key}->{'bits'}  || '0';
        my $mac = $ciphers{$key}->{'mac'}   || '';
        my $sec = $ciphers{$key}->{'sec'}   || '';
        my $tag = $ciphers{$key}->{'tags'}  || '';

        if ($format =~ m/^(?:15|15.12.15|old)/) {
            $name= $ciphers_names{$key}->{'osaft'} || '';
    #next if $key =~ m/0x/;    # dirty hack 'til %cipher is clean
            my $score= "0"; # dummy because we don't have scores in new structure
            printf(" %-30s %s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
                     $name, $sec, $ssl, $enc, $bit, $mac, $au, $kx, $score, $tag  );
        }

        if ($format =~ m/^(?:16|16.06.16|new|osaft)/) {
            $name= $ciphers_names{$key}->{'iana'} || '';
            $name= $ciphers_names{$key}->{'osaft'} || '';
            printf("%14s\t%-41s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
                    $key, $name, $ssl, $kx, $au, $enc, $bit, $mac, $tag  );
        }

        if ($format =~ m/^(?:openssl)/) {
            $name= $ciphers_names{$key}->{'openssl'} || '';
            printf("%19s - %-23s %-5s Kx=%-8s Au=%-4s Enc=%s(%s) Mac=%-4s %s\n",
                    $key, $name, $ssl, $kx,   $au,   $enc, $bit, $mac,    $tag  );
        }

    }
    if ($format =~ m/^(?:16|16.06.16|new|osaft)/) {
        printf("=%s+%s+%s+%s+%s+%s+%s+%s+%s\n",
               "-" x 14, "-" x 47, "-" x 7, "-" x 7, "-" x 7, "-" x 7, "-" x 7, "-" x 7, "-" x 11 );
    }
    return;
}; # show_ciphers
#_____________________________________________________________________________
#___________________________________________________ initialization methods __|

our @_keys;

sub _ciphers_init_iana  {
    my @keys;

    vprint "initialize from IANA tls-parameters.txt ...";
    foreach my $key (keys %OSaft::Ciphers::_ciphers_iana) {
        if (grep{/^$key$/} @keys) {
            _warn(" duplicate IANA key: »$key«");
        } else {
            push(@keys, $key);
        }
        $ciphers_const{$key}->{'iana'} = $OSaft::Ciphers::_ciphers_iana{$key}[0] || '';
        $ciphers_names{$key}->{'iana'} = $OSaft::Ciphers::_ciphers_iana{$key}[0] || '';
        $ciphers{$key}->{'rfc'} = $OSaft::Ciphers::_ciphers_iana{$key}[1] || '';
        $ciphers{$key}->{'dtls'}= $OSaft::Ciphers::_ciphers_iana{$key}[2] || '';
    }
    undef %OSaft::Ciphers::_ciphers_iana;

    # correct IANA settings (new in June 2016)
    foreach my $key (qw(0xA8 0xA9 0xAA 0xAB 0xAC 0xAD 0xAE)) {
        $ciphers{'0xCC,' . $key}->{'rfc'} = "7905";
    }
    vprint "  keys:    " . ($#keys + 1);
    vprint "  ciphers: " . scalar(keys %ciphers);
    return @keys;
}; # _ciphers_init_iana

sub _ciphers_init_osaft {
    vprint "initialize from OSaft settings ...";
    foreach my $key (sort keys %{OSaft::Ciphers::_ciphers_osaft}) { ## no critic qw(Subroutines::ProtectPrivateSubs)
        if (grep{/^$key$/} @_keys) {
            v2print("  found O-Saft key: »$key«");
        } else {
            v2print("  new   O-Saft key: »$key«");
            push(@_keys, $key);
            $ciphers{$key}->{'rfc'}  = "";
            $ciphers{$key}->{'dtls'} = "";
        }
        $ciphers{$key}->{'ssl'} = $OSaft::Ciphers::_ciphers_osaft{$key}[0] || '';
        $ciphers{$key}->{'keyx'}= $OSaft::Ciphers::_ciphers_osaft{$key}[1] || '';
        $ciphers{$key}->{'auth'}= $OSaft::Ciphers::_ciphers_osaft{$key}[2] || '';
        $ciphers{$key}->{'enc'} = $OSaft::Ciphers::_ciphers_osaft{$key}[3] || '';
        $ciphers{$key}->{'bits'}= $OSaft::Ciphers::_ciphers_osaft{$key}[4] || '0';
        $ciphers{$key}->{'mac'} = $OSaft::Ciphers::_ciphers_osaft{$key}[5] || '';
        $ciphers{$key}->{'sec'} = $OSaft::Ciphers::_ciphers_osaft{$key}[6] || '';
        $ciphers{$key}->{'tags'}= $OSaft::Ciphers::_ciphers_osaft{$key}[7] || '';
        $ciphers{$key}->{'score'} = "0";  # dummy because we don't have scores in new structure
        $ciphers_names{$key}->{'osaft'} = $OSaft::Ciphers::_ciphers_names{$key}[0] || '';
        $ciphers_const{$key}->{'osaft'} = $OSaft::Ciphers::_ciphers_names{$key}[1] || '';
#print "$key - $ciphers{$key}->{'ssl'} : $ciphers_names{$key}->{'osaft'} #\n";
    }
    # add misisng names and constants
    foreach my $key (sort keys %{OSaft::Ciphers::_ciphers_names}) { ## no critic qw(Subroutines::ProtectPrivateSubs)
        my $name  = $OSaft::Ciphers::_ciphers_names{$key}[0] || '';
        my $const = $OSaft::Ciphers::_ciphers_names{$key}[1] || '';
        if (! defined $ciphers_names{$key}->{'osaft'} ne "") {
            #print("  undef O-Saft name: $key : »$name«\n");
            $ciphers_names{$key}->{'osaft'} = $name;
            next;
        }
        if ($ciphers_names{$key}->{'osaft'} eq "") {
            #print("  emtpty O-Saft name: $key : »$name«\n");
            $ciphers_names{$key}->{'osaft'} = $name;
        }
    }
    undef %OSaft::Ciphers::_ciphers_const;
    undef %OSaft::Ciphers::_ciphers_names;
    undef %OSaft::Ciphers::_ciphers_osaft;
    #vprint "  keys:    " . ($#_keys + 1);
    vprint "  ciphers: " . scalar(keys %ciphers);
    return;
}; # _ciphers_init_osaft

sub _ciphers_init_openssl   {
    vprint "initialize data from »openssl ciphers -V« ...";
    foreach my $key (keys %OSaft::Ciphers::_ciphers_openssl_all) {
        if (grep{/^$key$/} @_keys) {
            _warn(" duplicate openssl key: »$key«");
        } else {
            push(@_keys, $key);
        }
        #print $key;
        $ciphers{$key}->{'ssl'} = $OSaft::Ciphers::_ciphers_openssl_all{$key}[0];
        $ciphers{$key}->{'kexx'}= $OSaft::Ciphers::_ciphers_openssl_all{$key}[1];
        $ciphers{$key}->{'auth'}= $OSaft::Ciphers::_ciphers_openssl_all{$key}[2];
        $ciphers{$key}->{'enc'} = $OSaft::Ciphers::_ciphers_openssl_all{$key}[3];
        $ciphers{$key}->{'bits'}= $OSaft::Ciphers::_ciphers_openssl_all{$key}[4];
        $ciphers{$key}->{'mac'} = $OSaft::Ciphers::_ciphers_openssl_all{$key}[5];
        $ciphers{$key}->{'tags'}= $OSaft::Ciphers::_ciphers_openssl_all{$key}[7] || '';
        my $name                = $OSaft::Ciphers::_ciphers_openssl_all{$key}[6];
        $ciphers_names{$key}->{'openssl'} = $name;
    }
    vprint "  ciphers: " . scalar(keys %ciphers);
    return;
}; # _ciphers_init_openssl

sub _ciphers_init_openssl_  {
    return;
}; # _ciphers_init_openssl_

sub _ciphers_init   {
    #? additional initializations for data structures

    # scan options, must be ckecked here also because this function will be
    # called before _main()
    foreach (@ARGV) {
        $VERBOSE++      if ($_ =~ /^--v$/);
    }

    @_keys = _ciphers_init_iana();
    _ciphers_init_osaft();
    undef @_keys;
    _ciphers_init_openssl();

    return;
}; # _ciphers_init

sub _main_help  {
    #? print help
    printf("# %s %s\n", __PACKAGE__, $VERSION);
    if (eval {require POD::Perldoc;}) {
        # pod2usage( -verbose => 1 );
        exec( Pod::Perldoc->run(args=>[$0]) );
    }
    if (qx(perldoc -V)) {
        # may return:  You need to install the perl-doc package to use this program.
        #exec "perldoc $0"; # scary ...
        printf("# no POD::Perldoc installed, please try:\n  perldoc $0\n");
    }
    return;
}; # _main_help

sub _main       {
    #? print own documentation
    if ($#ARGV < 0) { _main_help; exit 0; }

    # got arguments, do something special
    while (my $arg = shift @ARGV) {
        # ----------------------------- options
        $VERBOSE++          if ($arg =~ /^--v$/);
        # ----------------------------- commands
        print "$VERSION\n"  if ($arg =~ /^version/i);
        show_overview()     if ($arg =~ /^overview/);
        show_names()        if ($arg =~ /^names/);
        show_const()        if ($arg =~ /^const/);
        show_alias()        if ($arg =~ /^alias(?:es)?/);
        show_rfc()          if ($arg =~ /^rfc/i);
        show_desc()         if ($arg =~ /^desc(?:ription)?/);
        show_desc()         if ($arg =~ /^ciphers.?desc(?:ription)?/);
        #show_ciphers($1)    if ($arg =~ /^ciphers=(.*)$/);  # 15|16|dump|osaft|openssl
        if ($arg =~ /^ciphers=(.*)$/) { show_ciphers($1); } # same as above, but keeps perlcritic quiet
        if ($arg =~ /^getter=?(.*)/)  { show_getter($1);  }
        if ($arg =~ /^key=?(.*)/)     { show_key($1);  }
        if ($arg !~ /^--h(?:elp)?/)   { next; }

        my $name = (caller(0))[1];
        print "# commands to show internal cipher tables:\n";
        foreach my $cmd (qw(overview names const alias rfc description)) {
            printf("\t%s %s\n", $name, $cmd);
        }
        print "# commands to show ciphers based on origin:\n";
        foreach my $cmd (qw(ciphers=osaft ciphers=openssl ciphers=iana ciphers=old)) {
            printf("\t%s %s\n", $name, $cmd);
        }
        print "# various commands:\n";
        foreach my $cmd (qw(ciphers=dumptab)) {
            printf("\t%s %s\n", $name, $cmd);
        }
        printf("\t$name getter=KEY #(KEY: sec, bit, mac, ssl, auth, keyx, enc, name)\n");
        printf("\t$name key=KEY #(KEY: )\n");
        printf("\t$name ciphers=dumptab > c.csv; libreoffice c.csv\n");
    }
    exit 0;
}; # _main

sub cipher_done {};             # dummy to check successful include

# complete initializations
_ciphers_init();

#_____________________________________________________________________________
#_____________________________________________________ public documentation __|

=pod

=head1 COMMANDS

If called from command line, like

  OSaft/Ciphers.pm [OPTIONS ..] [COMMANDS]

this modules provides following commands:

=over 4

=item version

- just print the module's version

=item description

- print description of all data structures

=item overview

- print overview if cipher description and name exists in internal lists

=item names

- print overview of various cipher suite names

=item const

- print overview of various cipher suite constant names

=item rfc

- print cipher suite name and corresponding RFCs

=item ciphers=dump

- print internal lists of ciphers (all data, internal format)

=item ciphers=osaft

- print internal lists of ciphers (internal format)

=item ciphers=openssl

- print internal lists of ciphers (format like "openssl ciphers -V")

=item ciphers=16

=back

=head1 OPTIONS

=over 4

=item --v

- print verbose messages (in CLI mode only).

=back

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

_main() if (! defined caller);

1;

