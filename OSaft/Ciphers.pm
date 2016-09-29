#!/usr/bin/perl
## PACKAGE {

=pod

=encoding utf8

=head1 NAME

OSaft::Ciphers - common perl module for O-Saft ciphers


########################  E X P E R I M E N T A L  #######################
######################  not used in O-Saft 16.09.16  #####################

=cut

#####
# perlcritic -3 OSaft/Ciphers.pm # -verbose 10
## tests:
#	OSaft/Ciphers.pm overview
#	OSaft/Ciphers.pm const
#	OSaft/Ciphers.pm names
#	OSaft/Ciphers.pm ciphers=osaft
#	OSaft/Ciphers.pm ciphers=openssl
#	OSaft/Ciphers.pm ciphers=old

# test resources with:
## /usr/bin/time --quiet -a -f "%U %S %E %P %Kk %Mk" OSaft/Ciphers.pm  names
## 0.12  0.00  0:00.12  96%  0k  6668k
## 0.11  0.00  0:00.11  98%  0k  6852k


#############
# RFC in OSaft/_ciphers_iana.pm abgeglichen mit https://tools.ietf.org/rfc/rfcXXXX.txt
#   d.h. keys passen zu den Konstanten
#############

# TODO: see comment at %cipher_names

########################  E X P E R I M E N T A L  #######################

package OSaft::Ciphers;

use strict;
use warnings;
use Carp;
our @CARP_NOT = qw(OSaft::Ciphers); # TODO: funktioniert nicht

use Readonly;
Readonly our $VERSION     => '16.09.21';    # official verion number of tis file
Readonly our $CIPHERS_SID => '@(#) Ciphers.pm 1.10 16/09/29 18:44:24';
Readonly my  $STR_UNDEF   => '<<undef>>';   # defined in osaft.pm

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
of the ciphers. All  L</COMMANDS> and L</OPTIONS>  are only for this additional 
functionality, please descritions there.

=head2 Used Functions

Following functions (methods) must be defined in the calling program:

None (06/2016).

=head1 VARIABLES

=over 4

=item %ciphers

Hash with all cipher suites and paramters of each suite. Indexed by cipher ID.

=item %ciphers_desc

=item %cipher_names

Hash with various names, identifiers and constants for each cipher suite.
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
                get_param
                get_sec
                get_ssl
                get_enc
                get_bits
                get_mac
                get_auth
                get_keyx
                get_score
                get_tags
                get_desc
                get_rfc
                get_dtls
                get_hex
                get_name
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

our %cipher_const = (
    #? list of cipher suite constant names, will be generated in _ciphers_init()
    #!#----------+---------------+---------------+---------------+------------+
    #!# key     => [qw( iana OpenSSL openssl osaft )],
    #!#                             (osaft: SSL_CK_ and TLS_ prefix missing) 
    #!#----------+---------------+---------------+---------------+------------+
	# iana		- aus _ciphers_iana.pm
	# OpenSSL	- aus _ciphers_??   (ssl.h, tls.h, ...)
	# openssl	- aus _ciphers_openssl_all.pm  (openssl ciphers -V)
	# osaft		- aus _ciphers_osaft.pm  (handgestrickt)
# ...
); # %cipher_names
#  defined in OSaft/_ciphers_iana.pm, OSaft/_ciphers_osaft.pm

our %cipher_names = (
    #? list of cipher suite names, will be generated in _ciphers_init()
    #!#----------+---------------+---------------+---------------+------------+
    #!# key     => [qw( iana OpenSSL openssl osaft )],
    #!#                             (osaft: SSL_CK_ and TLS_ prefix missing) 
    #!#----------+---------------+---------------+---------------+------------+
# ...
); # %cipher_names
#  defined in OSaft/_ciphers_iana.pm, OSaft/_ciphers_osaft.pm

our %cipher_alias = ( # TODO: list not yet used
    #!#----------+-------------------------------------+-----------------------,
    #!# constant =>     cipher suite name alias        # comment (where found)
    #!#----------+-------------------------------------+-----------------------,
# ...
); # %cipher_alias
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

=head2 get_sec( $cipher)

=head2 get_ssl( $cipher)

=head2 get_enc( $cipher)

=head2 get_bits($cipher)

=head2 get_mac( $cipher)

=head2 get_auth($cipher)

=head2 get_keyx($cipher)

=head2 get_score($cipher)

=head2 get_tags($cipher)

=head2 get_desc($cipher)

=head2 get_rfc( $cipher)

=head2 get_dtls($cipher)

Get information from internal C<%cipher> data structure.

=cut

# some people prefer to use a getter function to get data from objects
# each function returns a spcific value (column) from the %cipher table
# see %ciphers_desc about description of the columns
# returns STR_UNDEF if requested cipher is missing
sub get_param   {
    #? internal method to return required value from %cipher
    my ($cipher, $key) = @_;
    return $ciphers{$cipher}->{$key} || '' if ((grep{/^$cipher/} %ciphers)>0);
    return $STR_UNDEF;
}; # get_param
sub get_sec     { my $c=shift; return get_param($c, 'sec'); }
sub get_ssl     { my $c=shift; return get_param($c, 'ssl'); }
sub get_enc     { my $c=shift; return get_param($c, 'enc'); }
sub get_bits    { my $c=shift; return get_param($c, 'bit'); }
sub get_mac     { my $c=shift; return get_param($c, 'mac'); }
sub get_auth    { my $c=shift; return get_param($c, 'au');  }
sub get_keyx    { my $c=shift; return get_param($c, 'kx');  }
sub get_tags    { my $c=shift; return get_param($c, 'tag'); }
sub get_rfc     { my $c=shift; return get_param($c, 'rfc'); }
sub get_dtls    { my $c=shift; return get_param($c, 'dtls'); }
sub get_score   { my $c=shift; return $STR_UNDEF; } # obsolete since 16.06.16

sub get_desc    { my $c=shift;
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

=head2 get_hex($cipher)

Get cipher's hex key from C<%cipher_names> or C<%cipher_alias> data structure.

=head2 get_name($cipher)

Check if given C<%cipher> name is a known cipher.

=cut

sub get_hex     {
    # find hex key for cipher in %cipher_names or %cipher_alias
    my $c = shift;
    foreach my $k (keys %cipher_names) { # database up to VERSION 14.07.14
        return $k if (($cipher_names{$k}[0] eq $c) or ($cipher_names{$k}[1] eq $c));
    }
    foreach my $k (keys %cipher_alias) { # not yet found, check for alias
        return $k if ($cipher_alias{$k}[0] eq $c);
    }
    return '';
} # get_hex

sub get_name    {
    # check if given cipher name is a known cipher
    # checks in %ciphers if nof found in %cipher_names
    my $cipher  = shift;
    return $cipher if ((grep{/^$cipher/} %ciphers)>0);
    _trace("get_name: search $cipher");
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
} # get_name

=pod

=head2 printciphers($format)

Print C<%ciphers> data structure in specified format.

Supported formats are:
* openssl       - like openssl ciphers -V
* osaft         - most important data
* dump          - all available data
* 15.12.15      - format like in version 15.12.15 (for compatibility)

=cut

sub printciphers {
    #? print internal list of ciphers in specified format
    my $format = shift;

    print  "= internal lists of ciphers\n";

#   printf("=%14s\t%-39s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
#            "key", "name", "sec", "ssl", "enc", "bit", "mac", "au", "kx", "score", "tag" );
#	format=15.12
    if ($format =~ m/^(?:16|16.06.16|new|osaft)/) {
        printf("=%14s\t%-47s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
               "key", "name", "ssl", "kx", "au", "enc", "bit", "mac", "tag" );
        printf("=%s+%s+%s+%s+%s+%s+%s+%s+%s\n",
               "-" x 14, "-" x 47, "-" x 7, "-" x 7, "-" x 7, "-" x 7, "-" x 7, "-" x 7, "-" x 11 );
    }

    foreach my $key (sort keys %ciphers) {

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
    #next if $key =~ m/0x/;    # dirty hack 'til %cipher is clean
            my $score= '0'; # dummy because we don't have scores in new structure
            printf(" %-30s %s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
                     $name, $sec, $ssl, $enc, $bit, $mac, $au, $kx, $score, $tag  );
        }

        if ($format =~ m/^(?:16|16.06.16|new|osaft)/) {
            $name= $cipher_names{$key}->{'iana'} || '';
            $name= $cipher_names{$key}->{'osaft'} || '';
            printf("%14s\t%-41s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
                    $key, $name, $ssl, $kx, $au, $enc, $bit, $mac, $tag  );
        }

        if ($format =~ m/^(?:openssl)/) {
            $name= $cipher_names{$key}->{'openssl'} || '';
            printf("%19s - %-23s %-5s Kx=%-8s Au=%-4s Enc=%s(%s) Mac=%-4s %s\n",
                    $key, $name, $ssl, $kx,   $au,   $enc, $bit, $mac,    $tag  );
        }

    }
    if ($format =~ m/^(?:16|16.06.16|new|osaft)/) {
        printf("=%s+%s+%s+%s+%s+%s+%s+%s+%s\n",
               "-" x 14, "-" x 47, "-" x 7, "-" x 7, "-" x 7, "-" x 7, "-" x 7, "-" x 7, "-" x 11 );
    }
    return;
}; # printciphers

sub print_desc_name {
    print  "= overview if cipher description and name exists in internal lists\n";
    printf("=%s+%s+%s+%s+%s\n", "-" x 14, "-" x 7, "-" x 7, "-" x 7, "-" x 7);
    printf("= %13s\t%s\t%s\t%s\t%s\n",  "",  "ciphers", "cipher_", "cipher_", "name +");
    printf("= %13s\t%s\t%s\t%s\t%s\n", "key ", " desc", " name",   " alias",  " desc");
    printf("=%s+%s+%s+%s+%s\n", "-" x 14, "-" x 7, "-" x 7, "-" x 7, "-" x 7);
    #rint  "  key    *       *       *    yes";
    #rint  "  key    *               *    no ";
    foreach my $key (sort keys %ciphers) {
         my $both  = "no";
         my $desc  = " ";
         my $name  = " ";
         my $alias = " ";
         $desc  = "*" if $ciphers{$key};
         $name  = "*" if $cipher_names{$key}->{'osaft'};
         $alias = "*" if defined $cipher_alias{$key};
         $both  = "yes" if ($desc eq "*" and $name eq "*");
         printf("%14s\t%s\t%s\t%s\t%s\n", $key, $desc, $name, $alias, $both);
    }
    printf("=%s+%s+%s+%s+%s\n", "-" x 14, "-" x 7, "-" x 7, "-" x 7, "-" x 7);
    return;
}; # print_desc_name

sub print_const {
    print  "= overview of various cipher suite constant names
=   description of columns:
=       key     - hex key for cipher suite
=       iana    - constant of cipher suite as defined by IANA
=       OpenSSL - constant of cipher suite used in openssl's *.h files
=       osaft   - constant of cipher suite used by O-Saft
=       o=i o=o - yes if IANA's cipher suite names is same as O-Saft's name
";
    printf("=%s+%s+%s+%s+%s-%s\n", "-" x 14, "-" x 39, "-" x 31, "-" x 31, "-" x 7, "-" x 7);
#TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA
    printf("=%s|    osaft = \n", " " x 119);
    printf("= %13s\t\t%-37s\t%-31s\t%-23s\t%s\n", "key ", "iana", "OpenSSL", "osaft", "| iana openssl");
    printf("=%s+%s+%s+%s+%s+%s\n", "-" x 14, "-" x 39, "-" x 31, "-" x 31, "-" x 7, "-" x 7);
    foreach my $key (sort keys %ciphers) {
         my $const1 = $cipher_const{$key}->{'iana'}    || "";
         my $const2 = $cipher_const{$key}->{'OpenSSL'} || "";
         my $const3 = $cipher_const{$key}->{'osaft'}   || "";
         my $o_i = "no";
            $o_i = "yes" if ($const1 eq ("TLS_" . $const3));
         my $o_o = "no";
            $o_o = "yes" if ($const2 eq ("TLS_" . $const3));
         printf("%14s\t%-37s\t%-31s\t%-31s\t%s\t%s\n", $key, $const1, $const2, $const3, $o_i, $o_o);
    }
    printf("=%s+%s+%s+%s+%s+%s\n", "-" x 14, "-" x 39, "-" x 31, "-" x 31, "-" x 7, "-" x 7);
    return;
}; # print_const

sub print_names {
    print  "= overview of various cipher suite names
=   description of columns:
=       key     - hex key for cipher suite
=       OpenSSL - name of cipher suite used in openssl's *.h files
=       openssl - name of cipher suite used by openssl executable
=       osaft   - name of cipher suite used by O-Saft
=       o=o     - yes if openssl's cipher suite names is same as O-Saft's name
";

    printf("=%s+%s+%s+%s+%s\n", "-" x 14, "-" x 23, "-" x 23, "-" x 23, "-" x 7);
    printf("= %13s\t\t%-23s\t%-23s\t%-15s\t%s\n", "key ", "OpenSSL", "openssl", "osaft", "openssl=osaft");
    printf("=%s+%s+%s+%s+%s\n", "-" x 14, "-" x 23, "-" x 23, "-" x 23, "-" x 7);
    foreach my $key (sort keys %ciphers) {
         my $name1 = $cipher_names{$key}->{'openssl'} || "";
         my $name2 = $cipher_names{$key}->{'osaft'}   || "";
         my $both  = "no";
            $both  = "yes" if ($name1 eq $name2);
         printf("%14s\t%-23s\t%-23s\t%-23s\t%s\n", $key,
                $cipher_names{$key}->{'OpenSSL'} || "",
                $name1, $name2, $both,
               );
    }
    printf("=%s+%s+%s+%s+%s\n", "-" x 14, "-" x 23, "-" x 23, "-" x 23, "-" x 7);
    return;
}; # print_names

######################################################
# print_names_o-o {
#   print  "=    openssl O-Saft iden-";
#   print  "= key  name  name   tical";
#   print  "=----+------+----+-------";
#   print  "  key DHE-   DHE-   yes  ";
#   print  "  key DHE-   EDH-   no   ";
# }; # 

# print_const_o-o {
#   print  "=    openssl O-Saft iden-";
#   print  "= key const  const  tical";
#   print  "=----+------+----+-------";
#   print  "  key TLS_   TLS_   yes  ";
#   print  "  key TLS_   PCT_   no   ";
# }; # 

# print_descr {
#   print       "=     key	ssl	keyx		auth	enc	bits	mac	sec	tags";
#   print       "=-------------+-------+---------------+-------+-------+-------+-------+-------+----";
#                0x01,0x00,0x80	TLS 1.2	ECDH/ECDSA	ECDH	AES	128	SHA256	HIGH
#   print  " key  TLS_  TLS_  DHE_   TLS- ";
# }; # 
######################################################

sub print_rfc   {
    print  "= cipher suite and corresponding RFCs\n";
    printf("=%s+%s+%s\n", "-" x 14, "-" x 15, "-" x 23);
    printf("= %13s\t\t%s\t%s\n", "key ", "RFC", "OpenSSL");
    printf("=%s+%s+%s\n", "-" x 14, "-" x 15, "-" x 23);
    foreach my $key (sort keys %ciphers) {
         my $rfc = $ciphers{$key}->{'rfc'} || "";
            $rfc = "RFC$rfc" if ($rfc ne "");
         printf("%14s\t%-15s\t%-23s\n", $key,
                $rfc,
                $cipher_names{$key}->{'osaft'} || "",
               );
         # TODO: in 'rfc' können mehrer stehen, durch Komma getrennt
    }
    printf("=%s+%s+%s\n", "-" x 14, "-" x 15, "-" x 23);
    return;
}; # print_names


# internal methods

our @_keys;

sub _ciphers_init_iana {
    my @keys;

    vprint "initialize from IANA tls-parameters.txt ...";
    foreach my $key (keys %OSaft::Ciphers::_ciphers_iana) {
        if (grep{/^$key$/} @keys) {
            _warn(" duplicate IANA key: »$key«");
        } else {
            push(@keys, $key);
        }
        $cipher_const{$key}->{'iana'} = $OSaft::Ciphers::_ciphers_iana{$key}[0] || '';
        $cipher_names{$key}->{'iana'} = $OSaft::Ciphers::_ciphers_iana{$key}[0] || '';
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
        $cipher_names{$key}->{'osaft'} = $OSaft::Ciphers::_ciphers_names{$key}[0] || '';
        $cipher_const{$key}->{'osaft'} = $OSaft::Ciphers::_ciphers_names{$key}[1] || '';
#print "$key - $ciphers{$key}->{'ssl'} : $cipher_names{$key}->{'osaft'} #\n"; 
    }
    undef %OSaft::Ciphers::_ciphers_const;
    undef %OSaft::Ciphers::_ciphers_names;
    undef %OSaft::Ciphers::_ciphers_osaft;
    #vprint "  keys:    " . ($#_keys + 1);
    vprint "  ciphers: " . scalar(keys %ciphers);
    return;
}; # _ciphers_init_osaft

sub _ciphers_init_openssl {
    vprint "initialize data from »openssl ciphers -V« ...";
    foreach my $key (keys %OSaft::Ciphers::_ciphers_openssl_all) {
        if (grep{/^$key$/} @_keys) {
            _warn(" duplicate openssl key: »$key«");
        } else {
            push(@_keys, $key);
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
    vprint "  ciphers: " . scalar(keys %ciphers);
    return;
}; # _ciphers_init_openssl

sub _ciphers_init_openssl_ {
    return;
}; # _ciphers_init_openssl_

sub _ciphers_init {
    #? additional initializations for data structures

    # scan options, must be ckecked her also because this function will be
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

sub _main       {
    #? print own documentation
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
        # ----------------------------- options
        $VERBOSE++          if ($arg =~ /^--v$/);
        # ----------------------------- commands
        print "$VERSION\n"  if ($arg =~ /^version/i);
        print_rfc()         if ($arg =~ /^rfc/i);
        print_desc_name()   if ($arg =~ /^overview/);
        print_names()       if ($arg =~ /^names/);
        print_const()       if ($arg =~ /^const/);
        #printciphers($1)    if ($arg =~ /^ciphers=(.*)$/);  # 15|16|dump|osaft|openssl
        if ($arg =~ /^ciphers=(.*)$/) { printciphers($1); }  # same as above, but keeps perlcritic quiet
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
