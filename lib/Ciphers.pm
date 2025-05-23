#!/usr/bin/perl -CADSio
## PACKAGE {

#!# Copyright (c) 2025, Achim Hoffmann
#!# This  software is licensed under GPLv2. Please see o-saft.pl for details.

package Ciphers;
use strict;
use warnings;
use utf8;
use Carp;
our @CARP_NOT   = qw(Ciphers); # TODO: funktioniert nicht

# for description of "no critic" pragmas, please see  t/.perlcriticrc  and
# SEE Perl:perlcritic

## no critic qw(RegularExpressions::RequireExtendedFormatting)
## no critic qw(Variables::ProhibitPackageVars)

# test resources with:
# /usr/bin/time --quiet -a -f "%U %S %E %P %Kk %Mk" lib/Ciphers.pm  alias
# 0.06  0.01  0:00.07 100%  0k  9756k  # 3/2023
# 0.02  0.00  0:00.02 100%  0k  9496k  # 3/2022
# 0.02  0.00  0:00.03 100%  0k  9924k  # 11/2022
# 0.02  0.00  0:00.02 100%  0k  8804k  # 12/2023
# 0.03  0.00  0:00.03 100%  0k 10176k  # 01/2024
# 0.04  0.00  0:00.05 100%  0k 10024k  # 07/2024
# 0.04  0.00  0:00.05 100%  0k 10052k  # 01/2025
# 0.04  0.00  0:00.05 100%  0k  9988k  # 02/2025

#_____________________________________________________________________________
#___________________________________________________ package initialisation __|

my  $SID_ciphers= "@(#) Ciphers.pm 3.67 25/04/09 00:10:16";
our $VERSION    = "24.09.24";   # official verion number of this file

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
    our @EXPORT_OK = qw(
        %ciphers
        %ciphers_desc
        $cipher_results
        %ciphers_notes
        %ciphers_cfg
    );
#   methods not exported, see METHODS description above
}

use OText       qw(%STR);
use OCfg;

# SEE Note:Stand-alone
$::osaft_standalone = 0 if not defined $::osaft_standalone;

#_____________________________________________________________________________
#_____________________________________________________ public documentation __|

# More public documentation, see start of methods section, and at end of file.

=pod

=encoding utf8


=head1 NAME

Ciphers - Perl module to define cipher suites for O-Saft


=head1 SYNOPSIS

=over 2

=item  use Ciphers;     # from within Perl code

=item  Ciphers.pm       # on command-line will print help

=item  Ciphers.pm --usage   # on command-line will show commands to print data

=back


=head1 DESCRIPTION

Utility package for O-Saft (o-saft.pl and related tools). This package contains
the primary data structure for cipher suites. Common L</VARIABLES> and L</METHODS>
are declares and defined to be used in the calling tool.

The documentation is intended for developers. Users should read any of the help
texts for example provided by O-Saft, i.e. C<o-saft.pl --help>.

This module provides  additional functionality  to list and check the used data
structures for the cipher suites. All  L</COMMANDS> and L</OPTIONS>  of this tool
are only for this additional functionality, please read descriptions there.

=head2 Used Functions

Following functions (methods) must be defined in the calling program:

None (03/2022).


=head1 CONCEPT

The main data structure is  C<%ciphers>, which will be defined herein.
Ciphers (more precisely: cipher suites) are defined statically as Perl __DATA__
herein. Each cipher is defined statically in one line with TAB-separated values
for example:

    0x0300003D HIGH  HIGH  TLSv12  RSA  RSA  AES  256  SHA256 .. AES256-SHA256

For a more detailed description, please use:

    lib/Ciphers.pm description
    lib/Ciphers.pm +test-ciphers-description

or consult the source code directly, in particular  C<%ciphers_desc>.

The main key -aka ID- to identify a cipher suite is a 32-bit key where the last
16 bits are the numbers as defined by IANA and/or various RFCs.
This key is also used in all other data structures related to ciphers.

Each cipher suite is defined as a Perl array (see above)  and will be converted
to a Perl hash at initialisation like:

    '0x0300003D' => { ssl=>"TLSv12", keyx=>"RSA", enc=>"AES", ... },

Such a hash is simpler to use. Finally a getter method (see L</METHODS>) is
provided for each value.

=cut

#This approach to specify the definition,  which must be done by developers,  is
#based on the consideration that the data structure needs to be  maintained very
#carefully. Therefore the description of  all (known) cipher suites is done in a
#simple table, which just contains TAB-separated words.  This table will then be
#converted into the %ciphers hash automatically when this module is loaded. It's
#the author's opinion, that tabular data is more easy to maintain by humans than
#structured data.

=pod

=head3 Variables

All variables except C<$cipher_results> are constants, and hence read-only. There
is no need to change them in the calling program.

=head3 Methods

Because all variables are constants, mainly getter methods are provided.
The only setter method is C<set_sec> which is used to redefine the security value
of an cipher by the user with the option  "--cfg-cipher=CIPHER=value"

=head3 Testing

The getter methods can be used directly, see:  lib/Ciphers.pm --usage

=head3 Documentation

This documentation describes the public variables and methods only, but not the
internal ones, in particular the  C<show_*()> functions.  Please see the source
itself for that.


=head1 VARIABLES

=head3 %ciphers

Hash with all cipher suites and paramters of each suite. Indexed by cipher ID.

=head3 %ciphers_desc

Describes the data structure in C<%ciphers>.

=head3 $cipher_results

Pointer to hash with all checked ciphers.

=head3 %ciphers_notes

Notes and comments for a specific cipher, documentation only.
Will be referenced in C<%ciphers>.

=head3 $cipher_cfg

Cipher-specific settings and configurations.
They are not used here, but they're all related to ciphers, hence defined here.

=cut

#_____________________________________________________________________________
#________________________________________________ public (export) variables __|

our %ciphers        = ( # list of all ciphers
    # will be generated in _ciphers_init() from <DATA> (at end of this file)
    #--------------+-------+-------+----+----+----+----+----+----+----+-----------+-----------+-----+
    # key       => [qw( openssl sec ssl  keyx auth enc  bits mac  rfc  name;alias  const       notes )],
    #--------------+-------+-------+----+----+----+----+----+----+----+-----------+-----------+-----+
    #--------------+-------+-------+----+----+----+----+----+----+----+-----------+-----------+-----+
# ...
); # %ciphers

our %ciphers_desc   = ( # description of %ciphers table
    'head'          => [qw( openssl sec  ssl  keyx auth enc  bits mac  rfc  names const notes)],
                            # array of all culumns used most tables (including
                            # the definition below in DATA);
                            # abbreviations used by openssl:
                            # SSLv2, SSLv3, TLSv1, TLSv1.1, TLSv1.2
                            # Kx=  key exchange (DH is diffie-hellman)
                            # Au=  authentication
                            # Enc= encryption with bit size
                            # Mac= mac encryption algorithm
                            # 
    'hex'      => 'Hex Code',       # hex key for cipher suite
                            #
    'openssl'  => 'OpenSSL STRENGTH', # LOW, MEDIUM, HIGH as reported by openssl 0.9.8 .. 1.0.1h
                            # WEAK as reported by openssl 0.9.8 as EXPORT
                            # weak unqualified by openssl or known vulnerable
                            # NOTE: weak includes NONE (no security at all)
                            # high unqualified by openssl, but considerd secure
    'sec'      => 'Security',       # weak, medium, high
                            # weak unqualified by openssl or known vulnerable
                            # high unqualified by openssl, but considerd secure
    'ssl'      => 'SSL/TLS Version',# Protocol Version:
                            # SSLv2, SSLv3, TLSv1, TLSv11, TLSv12, TLSv13, DTLS0.9, DTLS1.0, PCT
                            # NOTE: all SSLv3 are also TLSv1, TLSv11, TLSv12
                            # (cross-checked with sslaudit.ini)
    'keyx'     => 'Key Exchange',   # DH, ECDH, ECDH/ECDSA, RSA, KRB5, PSK, SRP, GOST, ECCPWD
                            # last column is a : separated list (only export from openssl)
                            # different versions of openssl report  ECDH or ECDH/ECDSA
    'auth'     => 'Authentication', # None, DSS, RSA, ECDH, ECDSA, KRB5, PSK, GOST01, GOST94
    'enc'      => 'Encryption Type',# Algorithm: None, AES, AESCCM, AESGCM, ARIA, CAMELLIA, DES, 3DES, FZA, GOST89, IDEA, RC4, RC2, SEED
    'bits'     => 'Encryption Size',# Key size in bits
    'enc_size' => 'Block Size',     # encryption block size in bits
    'mac'      => 'MAC/Hash Type',  # Algorithm: MD5, SHA1, SHA256, SHA384, AEAD, GOST89, GOST94
    'mac_size' => 'MAC/Hash Size',  # size of MAC in bits (usually coded in its name (type)
#   'dtls'     => 'DTLS OK', # Y  if cipher is compatible for DTLS, N  otherwise
#                            # (information from IANA)
    'rfc'      => 'RFC(s)',         # RFC number where cipher was defined
    'pfs'      => 'PFS',            # )f cipher ha perfect forward secrecy
    'suite'    => 'Cipher Suite',   # cipher suite name, mainly those used by OpenSSL
    'name'     => 'OpenSSL Name',   # cipher suite name used by OpenSSL
    'names'    => 'Names, Aliases', # Comma-separated list of cipher suite name and aliases
    'const'    => 'Constant Names', # Comma-separated list of cipher suite constants
    'notes'    => 'Notes/Comments', # Comma-separated list of notes and comments
                            # for this cipher suite; for eaxmple: EXPORT, OSX
                            # each value is used as key to %ciphers_notes
                            # 
    'sample'        => { # example
      '0x0300003D'  => [split /\s+/x, q(HIGH HIGH TLSv12 RSA  RSA  AES  256  SHA256 5246 AES256-SHA256,Alias RSA_WITH_AES_256_SHA256,RSA_WITH_AES_256_CBC_SHA256 L )],
                            # qw// would result in Perl warning:
                            #   Possible attempt to separate words with commas
                            # q// is one word, hence it must be splitted to become an array
        },
    'additional_notes'  => <<'EoNOTE',

Note about constant names:
  Depending on the source of the constant, a different prefix in the name is
  used, such as TLS_ or SSL_ or SSL_CK_ or SSL3_CK_ or TLS1_CK_ .
  Hence no prefix at all is used here.
Note about TLS version:
  Usually the lowest/oldest protocol version is shown. But this cipher suite
  may also be used in a newer protocol version also.
  Following normalised strings are used for protocol versions:
      SSLv2, SSLv3, DTLS0.9, DTLS1.0, TLSv10, TLSv11, TLSv12, TLSv13, PCT
  SSL/TLS  is used for pseudo cipher suites.
EoNOTE
); # %ciphers_desc

our $cipher_results = {};
    #? list of checked ciphers per SSL/TLS version
my  $cipher_results_desc = <<'EoDESC';
=---------------+------+----------------------------+----------------------+
=  ssl       => {
=       key    => [ supported, cipher parameters ], # cipher suite name
=  }
=---------------+------+----------------------------+----------------------+
= 'SSLv3'    => {
=      '0x02010080' => [ yes, '' ],                 # RC4-MD5
=      '0x03000004' => [ yes, '' ],                 # RC4-MD5
=      '0x02FF0810' => [ no,  '' ],                 # NULL
= },
= 'TLSv12'   => {
=      '0x0300006B' => [ yes, 'dh: 2048 bits' ],    # DHE-RSA-AES256-SHA256
=      '0x0300003D' => [ yes, '' ],                 # AES256-SHA256
= },
= '_admin'   => {   # for internal use
=      'TLSv12'     => { ... },  # TODO: ...
= },
=---------------+------+----------------------------+----------------------+
EoDESC

our %ciphers_notes  = ( # list of notes and comments for ciphers
    # these texts are referenced in %ciphers
    #------------------+---------,
    # hex       =>      'text'   ,
    #------------------+---------,
    #------------------+---------,
# ...
); # %ciphers_notes

our %ciphers_cfg    = ( #  cipher-specific configurations
   # not yet used
); # %ciphers_cfg

#_____________________________________________________________________________
#_________________________________________________________ internal methods __|

# SEE Perl:Undefined subroutine
*_trace   = sub { print(join(" ", "#${0}::",    @_), "\n") if (0 < $OCfg::cfg{'trace'});   return; } if not defined &_trace;
*_trace2  = sub { print(join(" ", "#${0}::",    @_), "\n") if (2 < $OCfg::cfg{'trace'});   return; } if not defined &_trace2;
*_v_print = sub { print(join(" ", "#${0}: ",    @_), "\n") if (0 < $OCfg::cfg{'verbose'}); return; } if not defined &_v_print;
*_v2print = sub { print(join(" ", "#${0}: ",    @_), "\n") if (1 < $OCfg::cfg{'verbose'}); return; } if not defined &_v2print;
    # TODO: \n in print() above wrong if called stand-alone

#_____________________________________________________________________________
#__________________________________________________________________ methods __|

=pod

=head1 METHODS

No methods are exported. The full package name must be used, which improves the
readability of the program code. Methods intended for external use are:

=head3 is_valid_key($key

Return normalised key if it matches  /^(0x)?[0-9A-F]{8}$/,  return empty string
otherwise.

=head3 text2key($text)

Convert hex text to internal key: 0x00,0x3D --> 0x0300003D.

=head3 key2text($key)

Convert internal key to hex text: 0x0300003D --> 0x00,0x3D.

=head3 set_sec(   $cipher_key)

Set value for 'security' in for specified cipher key.

=cut

sub is_valid_intern_key {
    #? same as is_valid_key() but allows internal key with suffix -bug, -c also
    my $key = uc(shift);
       $key =~ s/^0X//g;
    return "" if $key !~ m/^[0-9A-F]{8}(?:-BUG|-C)?$/;  # BUG|C because of uc()
    return "0x$key";
} # is_valid_key

sub is_valid_key {
    #? return normalised key if m/^(0x)?[0-9A-F]{8}$/; empty string otherwise
    my $key = uc(shift);
       $key =~ s/^0X//g;
    return "" if $key !~ m/^[0-9A-F]{8}$/;
    return "0x$key";
} # is_valid_key

sub text2key    {
    #? return internal hex key for given hex, return as is if not hex
    my $txt = shift;
    my $key = uc($txt); # we use upper case only
       $key =~ s/(,|0X)//g;     # 0x00,0x26  --> 0026
    return $txt if ($key !~ m/^[0-9A-F]+$/); # unknown format, return as is
    return "0x$key" if (8 == length($key));
    if (4 < length($key)) {
       # SSLv2: quick&dirty: expects 6 characers
       $key = "0x02$key";       # 010080     --> 0x02010080
    } else {
       # SSLv3, TLSv1.x
       while (6 > length($key)) { $key = "0$key"; }
       $key = "0x03$key";       # 000026     --> 0x03000026
    }
    return $key;
} # text2key

sub key2text    {
    #? return internal hex key converted to openssl-style hex key
    # strips 0x03,0x00
    # return as is if not hex
    my $key = shift;
    return $key if not is_valid_key($key);  # unknown format, return as is
       # NOTE: invalid keys like 0x0300001E-bug should not be converted
       $key =~ s/0x//i;         #    0x0026  --> 0026 (necessary in test-mode only)
    if (6 < length($key)) {     #   from     -->     to
       $key =~ s/^42//;         # 0x42420001 -->   420001 ; internal use in future
       $key =~ s/^02//;         # 0x02010080 -->   010080
       $key =~ s/^0300//;       # 0x03000004 -->     0004
    }
       $key =~ s/(..)/,0x$1/g;  #       0001 --> ,0x00,0x04
       $key =~ s/^,//;          # ,0x00,0x04 -->  0x00,0x04
       $key =  "     $key" if (10 > length($key));
    return "$key";
} # key2text

sub set_sec     { my ($key, $val) = @_; $ciphers{$key}->{'sec'} = $val; return; }
    #? set value in $ciphers{$key}->{'sec'} hash

=pod

=head3 get_param( $cipher_key, $key)

=head3 get_openssl( $cipher_key)

=head3 get_ssl(   $cipher_key)

=head3 get_sec(   $cipher_key)

=head3 get_keyx(  $cipher_key)

=head3 get_auth(  $cipher_key)

=head3 get_enc(   $cipher_key)

=head3 get_bits(  $cipher_key)

=head3 get_mac(   $cipher_key)

=head3 get_dtls(  $cipher_key)

=head3 get_rfc(   $cipher_key)

=head3 get_name(  $cipher_key)

=head3 get_names( $cipher_key)

=head3 get_aliases($cipher_key)

Return all cipher suite names except the first cipher suite name.

=head3 get_const( $cipher_key)

=head3 get_consts($cipher_key)

=head3 get_note(  $cipher_key)

=head3 get_notes( $cipher_key)

=head3 get_encsize( $cipher_key)

Return encryption block size of cipher suite.

=cut

# some people prefer to use a getter function to get data from objects
# each function returns a spcific value (column) from the %ciphers table
# see %ciphers_desc about description of the columns
# returns $STR{UNDEF} if requested cipher (hex key) is missing
sub get_param   {
    #? internal method to return required value from %ciphers ($cipher is hex-key)
    #? returns array or string depending on calling context
    my ($hex, $key) = @_;
    #_trace("get_param($hex,$key)");
        $hex = text2key($hex);      # normalize cipher key
    # if (0 < (grep{/^$hex/i} %ciphers))  # TODO: brauchen wir das für defense programming?
    if ('ARRAY' eq ref($ciphers{$hex}->{$key})) {
        return wantarray ? @{$ciphers{$hex}->{$key}} : join(' ', @{$ciphers{$hex}->{$key}});
    } else {
        return               $ciphers{$hex}->{$key} || "";
    }
    return $STR{UNDEF}; # never reached
} # get_param

sub get_openssl { return  get_param(shift, 'openssl');  }
sub get_sec     { return  get_param(shift, 'sec'  );    }
sub get_ssl     { return  get_param(shift, 'ssl'  );    }
sub get_keyx    { return  get_param(shift, 'keyx' );    }
sub get_auth    { return  get_param(shift, 'auth' );    }
sub get_enc     { return  get_param(shift, 'enc'  );    }
sub get_bits    { return  get_param(shift, 'bits' );    }
sub get_mac     { return  get_param(shift, 'mac'  );    }
sub get_rfc     { return  get_param(shift, 'rfc'  );    }
sub get_name    { return (get_param(shift, 'names'))[0];}
#sub get_name    { my @n = get_param(shift, 'names'); print "# get_name: $n[0]"; return $n[0];}
sub get_names   { return  get_param(shift, 'names');    }
sub get_aliases { my @a = get_names(shift); return @a[1 .. $#a]; }
#or get_aliases { my @a = get_names(shift); shift @a; return @a; }
sub get_const   { return (get_param(shift, 'const'))[0];}
sub get_consts  { return  get_param(shift, 'const');    }
sub get_note    { return (get_param(shift, 'notes'))[0];}
sub get_notes   { return  get_param(shift, 'notes');    }

sub _get_name   {
    #? internal method to return cipher suite name when paramater is hex-key or cipher suite name
    # simple check: asumes a key, if it matches 0x
    my $txt = shift;
    return $txt if ($txt !~ m/0x/);
    return get_name($txt);
} # _get_name

sub get_encsize {
    #? return encryption block size, based on (OpenSSL's) cipher suite name
    #? $cipher is hex-key or cipher suite name
    my $name= _get_name(shift);
    return '128'        if ($name =~ m/AES/);
    return '64'         if ($name =~ m/Blowfish/i);
    return '128'        if ($name =~ m/CAMELLIA/);
    return '-'          if ($name =~ m/-CHACHA/);
    return '64'         if ($name =~ m/-CBC3/);
    return '64'         if ($name =~ m/-3DES/);
    return '-'          if ($name =~ m/DES-CBC/);   # 3DES and CBC3 matched before
    return '-?-'        if ($name =~ m/DES-CFB/);
    return '-?-'        if ($name =~ m/GOST/);
    return '64'         if ($name =~ m/IDEA/);
    return '-'          if ($name =~ m/NULL/);
    return '64'         if ($name =~ m/RC2-/);
    return '-'          if ($name =~ m/RC4/);
    return '128'        if ($name =~ m/SEED/);
    return '-?-';   # shoud be $STR{UNDEF}, but that's nasty in HTML
} # get_encsize

# following not yet used, as this information is defined in %ciphers
#
# =pod
# 
# =head3 get_encmode( $cipher_key)
# 
# Return type of encryption mode of cipher suite.
# 
# =head3 get_enctype( $cipher_key)
# 
# Return type of encryption of cipher suite.
# 
# =head3 get_mactype( $cipher_key)
# 
# Return type of MAC of cipher suite.
# 
# =cut
# 
# sub get_encmode {
#     #? return encryption mode, based on (OpenSSL's) cipher suite name
#     #? $cipher is hex-key or cipher suite name
#     # NOTE: use get_enc() instead
#     my $name= _get_name(shift);
#     return 'GCM'        if ($name =~ m/-GCM/);
#     return 'CBC'        if ($name =~ m/-CBC/);
#     return 'CBC'        if ($name =~ m/-CAMELLIA/);
#     return 'CBC'        if ($name =~ m/-IDEA/);
#     return 'CBC'        if ($name =~ m/-SEED/);
#     return 'CBC'        if ($name =~ m/-RC2/);
#     return '-'          if ($name =~ m/-RC4/);
#     return '-'          if ($name =~ m/-CHACHA20/);
#     return '-'          if ($name =~ m/-NULL/);
#     return 'CBC';   # anything else is CBC (i.e. if CBC is not part of the suite name)
# } # get_encmode
# 
# sub get_enctype {
#     #? return encryption type, based on (OpenSSL's) cipher suite name
#     #? $cipher is hex-key or cipher suite name
#     my $name= _get_name(shift);
#     return 'AES'        if ($name =~ m/-AES/);  # matches: -AES128 -AES256 -AES-
#     return 'AES'        if ($name =~ m/AES/);   # matches: AES128- AES256-
#     return 'ARIA'       if ($name =~ m/-ARIA/);
#     return 'CCM8'       if ($name =~ m/-CCM8/);
#     return 'CCM'        if ($name =~ m/-CCM/);
#     return 'CAMELLIA'   if ($name =~ m/-CAMELLIA/);
#     return 'CHACHA20'   if ($name =~ m/-CHACHA20/);
#     return 'CAST'       if ($name =~ m/-CAST/);
#     return 'GOST'       if ($name =~ m/-GOST/); # TODO: GOST01 and GOST89 and GOST94?
#     return 'IDEA'       if ($name =~ m/-IDEA/);
#     return 'SEED'       if ($name =~ m/-SEED/);
#     return '3DES'       if ($name =~ m/-CBC3/);
#     return '3DES'       if ($name =~ m/-3DES/);
#     return 'DES'        if ($name =~ m/-DES/);
#     return 'RC4'        if ($name =~ m/-RC4/);
#     return 'RC2'        if ($name =~ m/-RC2/);
#     return 'None'       if ($name =~ m/-NULL/);
#     return '-?-';   # shoud be $STR{UNDEF}, but that's nasty in HTML
# } # get_enctype
# 
# sub get_mactype {
#     #? return encryption key, based on (OpenSSL's) cipher suite name
#     #? $cipher is hex-key or cipher suite name
#     my $name= _get_name(shift);
#     return 'SHA384'     if ($name =~ m/-SHA384/);
#     return 'SHA256'     if ($name =~ m/-SHA256/);
#     return 'SHA128'     if ($name =~ m/-SHA128/);
#     return 'SHA'        if ($name =~ m/-SHA1/); # matches: -SHA1$
#     return 'SHA'        if ($name =~ m/-SHA/);  # matches: -SHA$
#     return 'MD5'        if ($name =~ m/-MD5/);
#     return 'MD4'        if ($name =~ m/-MD4/);
#     return 'RMD'        if ($name =~ m/-RMD/);
#     return 'POLY1305'   if ($name =~ m/-POLY1305/);
#     return 'GOST'       if ($name =~ m/-GOST/); # TODO: GOST01 and GOST89 and GOST94?
#     return 'AEAD'       if ($name =~ m/-GCM/);
#     return '-?-';   # shoud be $STR{UNDEF}, but that's nasty in HTML
# } # get_mactype

=pod

=head3 get_key(   $cipher_name)

Return hex key for given cipher name; searches in cipher suite names and in cipher
suite constants. Given name must match exactly.

=head3 get_data(  $cipher_key)

Return all data for given cipher key from internal C<%ciphers> data structure.

=head3 get_iana(  $cipher_key)

Return "yes" if cipher suite for given key is recommended by IANA, "no" otherwise.

=head3 get_pfs(   $cipher_key|$cipher_name)

Return "yes" if cipher suite for given key supports PFS, "no" otherwise.

=head3 get_keys_list()

Return list of all defined (internal) hex keys for cipher suites in C<%ciphers>.
Returns space-separetd string or array depending on calling context.

=head3 get_names_list()

Return list of all defined cipher suite names in C<%ciphers>.
Returns space-separetd string or array depending on calling context.

=cut

sub get_key     {
    #? return hex key for given cipher name; searches in cipher suite names and constants
    my $txt = shift;
    my $key = uc($txt);
       $key =~ s/X/x/g; # 0X... -> 0x...
    my $typ = 'key';
    # ah: too noisy here# _trace("get_key($txt)");
    TRY: {
        last TRY if defined $ciphers{$key}; # cipher's hex key itself
        $typ = 'names';
        foreach my $k (keys %ciphers) {     # keys are unique, hence ord not important
            $key = $k;
            my @names = get_names($key);    # returns aliases too
            last TRY if (0 < (grep{/^$txt$/i} @names));
        }
        # any other text, try to normalise ...  # example:  SSL_CK_NULL_WITH_MD5
        $typ = 'const';
        $txt =~ s/^(?:SSL[23]?|TLS1?)_//;   # strip any prefix: CK_NULL_WITH_MD5 
        $txt =~ s/^(?:CK|TXT)_//;           # strip any prefix: NULL_WITH_MD5
        foreach my $k (keys %ciphers) {
            $key = $k;
            my @names = get_consts($key);
            last TRY if (0 < (grep{/^$txt$/i} @names));
        }
        $typ = 'no key found';
    }
    # ah: too noisy here# _trace("get_key: found '$txt' in %cipher{$typ}");
    return $key if ($typ !~ /^no key/);
    OCfg::warn("521: $typ for '$txt'");  # most likely a programming error %cfg or <DATA> herein
    return '';
} # get_key

sub get_data    {
    #? return all data for given cipher key from internal %ciphers data structure
    my $key = shift;
    return $STR{UNDEF} if (not defined $ciphers{$key});
    # my @x = sort values %{$ciphers{$key}}; # lasy approach not used
    return join("\t", 
            get_param($key, 'openssl'),
            get_param($key, 'sec'  ),
            get_param($key, 'ssl'  ),
            get_param($key, 'keyx' ),
            get_param($key, 'auth' ),
            get_param($key, 'enc'  ),
            get_param($key, 'bits' ),
            get_param($key, 'mac'  ),
            get_param($key, 'rfc'  ),
            #get_param($key, 'dtls' ), # not yet implemented
            get_param($key, 'names'),
            get_param($key, 'const'),
            get_param($key, 'notes'),
    );
} # get_data

sub get_iana    {
    #? return "yes" if cipher suite is recommended by IANA, "no" otherwise
    my $key = shift;
       $key = text2key($key);       # normalize cipher key
    return (grep{ /$key/i} $OCfg::cfg{'cipherranges'}{'iana'}) ? "yes" : "no";
} # get_iana

sub get_pfs     {
    #? return "yes" if cipher suite supports PFS, "no" otherwise
    my $key  = shift;
    my $name = $key;
    if (not is_valid_key($key)) {
       $name = get_name($key);
    }
    return (($name =~ m/^(?:EC)?DHE/) or ($name =~ m/^(?:EXP-)?EDH-/)) ? "yes" : "no";
        # EDH- and EXP-EDH- for ancient names
} # get_pfs

sub get_keys_list   {
    #? return list of all defined (internal) hex keys for cipher suites in %ciphers
    my @keys = grep{ /^0x[0-9a-fA-F]{8}$/} keys %ciphers;   # only valid keys
    return wantarray ? (sort @keys) : join(' ', (sort @keys));
    # SEE Note:Testing, sort
} # get_keys_list 

sub get_names_list  {
    #? return list of all defined cipher suite names in %ciphers
    my @list;
    foreach my $key (sort keys %ciphers) {
        next if (not is_valid_key($key));   # extract only valid keys
        push(@list, get_name($key));
    }
    return wantarray ? (sort @list) : join(' ', (sort @list));
    # SEE Note:Testing, sort
} # get_names_list

=pod

=head3 find_consts()

Return all constants for which given cipher constant (pattern) matches.

=head3 find_keys( $cipher_pattern)

Return all hex keys for which given cipher name (pattern) matches.

=head3 find_keys_any( $cipher_pattern)

Return all cipher suite keys for which given key, name, alias or constant (pattern) matches.

=head3 find_names( $cipher_pattern)

Find all matching cipher names for given cipher name (pattern).

=head3 find_names_any( $cipher_pattern)

Return cipher names for all matching hex keys, cipher names, aliases or constants.

=head3 find_name( $cipher)

Find cipher key(s) for given cipher name or cipher constant.

=cut

sub find_consts     {
    #? return all constants for which given cipher constant (pattern) matches in %ciphers
    # NOTE: matches the primary cipher suite name only, not aliases or constants
    my $pattern =  shift;
       $pattern =~ s/:/|/g;
    my @list;
    _trace("find_consts($pattern)");
    foreach my $key (sort keys %ciphers) {
        my @const = grep{/$pattern/} get_consts($key);
        next if not @const;
        push(@list, @const);
    }
    return @list;
} # find_consts

sub find_keys       {
    #? return all hex keys for which given cipher name (pattern) matches in %ciphers
    my $pattern = shift;
    _trace("find_keys($pattern)");
    return map({get_key($_);} grep{/$pattern/} get_names_list());
} # find_keys

sub find_keys_any   {
    #? return all cipher suite keys for which given key, name, alias or constant (pattern) matches
    my $pattern =  shift;
       $pattern =~ s/:/|/g;
    # FIXME: hex keys must be upper case
    my @list;
    _trace("find_keys_any: search $pattern");
    # should match below: my $key = get_key($pattern);
    foreach my $key (sort keys %ciphers) {
        next if $key =~ m/^\s*$/;
        if ($key =~ m/$pattern/) {
            push(@list, $key);
            next;
        }
        # get name and all aliases
        my  @names = grep{/$pattern/} get_names($key);
        if (@names) {   push(@list, $key);  next; }
        # get constants
            @names = grep{/$pattern/} get_consts($key);
        if (@names) {   push(@list, $key);  next; }
    }
    return @list;
} # find_keys_any

sub find_names      {
    #? find all cipher suite names for which given cipher pattern matches in %ciphers
    #? pattern can be RegEx like GCM|CHACHA or OpenSSL-style pattern like GCM:CHACHA
    # NOTE: matches the primary cipher suite name only, not aliases or constants
    my $pattern =  shift;
       $pattern =~ s/:/|/g;
    _trace("find_names($pattern)");
    return grep{/$pattern/} get_names_list();
} # find_names

sub find_names_any  {
    #? find all cipher suite names for which given cipher pattern matches, key or name or constant
    my $pattern =  shift;
       $pattern =~ s/:/|/g;
    my @list;
    foreach my $key (find_keys_any($pattern)) { push(@list, get_name($key)); }
    return wantarray ? (@list) : join(' ', (sort @list));
    return @list;
} # find_names_any

sub find_name       {
    #? TODO  check if given cipher name is a known cipher
    #  checks in %ciphers, if not found search in all aliases and constants
    #  example: RC4_128_WITH_MD5 -> RC4-MD5 ;  RSA_WITH_AES_128_SHA256 -> AES256-SHA256
    # Note: duplicate name (like RC4_128_WITH_MD5) are no problem, because they
    #       use the same cipher suite name (like RC4-MD5).
# TODO: need $ssl parameter because of duplicate names (SSLv3, TLSv10)
    my $cipher  = shift;
    my @list;
    _trace("find_name: search $cipher");
    my $key = get_key($cipher);
    return $key if $key !~ m/^\s*$/;
    # try fuzzy search in names and const:
    foreach my $key (sort keys %ciphers) {
        my $name = get_name($key);
        next if not $name;
        next if $name =~ m/^\s*$/;
        if ($name !~ m/$cipher/i) {
            my @const = get_consts($key);
#dbx print "C = @const\n";
        # TODO
        }
        OCfg::warn("513: partial match for cipher name found '$cipher'");
        push(@list, $key);
    }
    return @list;
# TODO: # $rex_name = s/([_-])/.?/g; $rex_name = s/DHE/EDH/;
    #return $STR{UNDEF};
} # find_name

=pod

=head3 sort_names(@ciphers)

Sort ciphers according their strength. Returns list with most strongest first.

C<@ciphers> is a list of cipher suite names. These names should be those used by
openssl(1)  .

=head3 sort_results(%unsorted)

Sort ciphers according their strength. Returns list with most strongest first.

C<%unsorted> is a reference to a hash) of cipher suite hex keys.
=cut

sub sort_names      {
    #? sort array of cipher suite names according their strength
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

    _trace("sort_names(){ $cnt_in ciphers: @ciphers }");

    # Algorithm:
    #  1. remove all known @insecure ciphers from given list
    #  2. start building new list with most @strength cipher first
    #  3. add previously removed @insecure ciphers to new list

    # define list of RegEx to match openssl cipher suite names
    # each regex could be seen as a  class of ciphers with the same strength
    # the list defines the strength in descending order, most strength first
    # NOTE the list may contain pattern, which actually do not match a valid
    # cipher suite name; doese't matter, but may avoid future adaptions, see
    # warning at end also

    my @insecure = (
        qw((?:RC[24]))  ,               # all RC2 and RC4
        qw((?:CBC|DES)) ,               # all CBC, DES, 3DES
        qw((?:DSA|DSS)) ,               # all DSA, DSS
        qw((?:MD[2345])),               # all MD
        qw(DH.?(?i:anon)),              # Anon needs to be caseless
        qw((?:NULL))    ,               # all NULL
        qw((?:PSK.SHA)) ,               # all PSK-SHA (which are PSK-NULL-SHA)
        qw((?:SCSV|SSL2_UNFFINED)),     # dummy ciphers (avoids **WARNING: 412: for INFO_SCSV)
        qw((?:GREASE-)) ,               # dummy ciphers (avoids **WARNING: 412: for GREASE*)
    );
    my @strength = (
        qw(CECPQ1[_-].*?CHACHA)       ,
        qw(CECPQ1[_-].*?AES256.GCM)   ,
        qw(^(TLS_|TLS13[_-]))         , # TLS13_ for TLS13_GOSTR341112_256_*
        qw((?:ECDHE|EECDH).*?CHACHA)  , # 1. all ecliptical curve, ephermeral, GCM
        qw((?:ECDHE|EECDH).*?512.GCM) , # .. sorts -ECDSA before -RSA
        qw((?:ECDHE|EECDH).*?384.GCM) ,
        qw((?:ECDHE|EECDH).*?256.GCM) ,
        qw((?:ECDHE|EECDH).*?128.GCM) ,
        qw((?:EDH|DHE).*?CHACHA)      , # 2. all ephermeral, GCM
        qw((?:EDH|DHE).*?PSK)         ,
        qw((?:EDH|DHE).*?512.GCM)     , # .. sorts AES before CAMELLIA
        qw((?:EDH|DHE).*?384.GCM) ,
        qw((?:EDH|DHE).*?256.GCM) ,
        qw((?:EDH|DHE).*?128.GCM) ,
        qw(ECDH[_-].*?CHACHA)   ,       # 3. all ecliptical curve, GCM
        qw(ECDH[_-].*?512.GCM)  ,       # .. sorts -ECDSA before -RSA
        qw(ECDH[_-].*?384.GCM)  ,
        qw(ECDH[_-].*?256.GCM)  ,
        qw(ECDH[_-].*?128.GCM)  ,
        qw(ECDHE.*?CHACHA),             # 4. all remaining ecliptical curve, ephermeral
        qw(ECDHE.*?512) ,
        qw(ECDHE.*?384) ,
        qw(ECDHE.*?256) ,
        qw(ECDHE.*?128) ,
        qw(ECDH[_-].*?CHACHA),          # 5. all remaining ecliptical curve
        qw(ECDH[_-].*?512) ,
        qw(ECDH[_-].*?384) ,
        qw(ECDH[_-].*?256) ,
        qw(ECDH[_-].*?128) ,
        qw(ECCPWD[_-])  ,               # 6. unknown ecliptical curve
        qw(AES)     ,                   # 7. all AES and specials
        qw(KRB5)    ,
        qw(SRP)     ,
        qw(PSK)     ,
        qw(GOST)    ,
        qw((?:IANA|LEGACY)[_-]GOST2012),# 
        qw(FZA)     ,
        qw((?:PSK|RSA).*?CHACHA),
        qw(CHACHA)  ,
        qw((?:EDH|DHE).*?CHACHA),       # 8. all DH
        qw((?:EDH|DHE).*?512) ,
        qw((?:EDH|DHE).*?384) ,
        qw((?:EDH|DHE).*?256) ,
        qw((?:EDH|DHE).*?128) ,
        qw((?:EDH|DHE).*?(?:RSA|DSS)) ,
        qw(AEGIS) ,                     # 9. unknown strength
        qw(CAMELLIA) ,
        qw((?:SEED|IDEA|ARIA|SM4)),
        qw(^(?:SHA256-|SHA384-)),
        qw(RSA[_-]) ,                   # 10.
        qw(DH[_-])  ,
        qw(RC)      ,
        qw(EXP)     ,                   # 11. Export ...
        qw(AEC.*?256) ,                 # insecure
        qw(AEC.*?128) ,
        qw(AEC)     ,
        qw(ADH.*?256) ,                 # no encryption
        qw(ADH.*?128) ,
        qw(ADH)     ,
        qw(PCT_)    ,                   # not an SSL/TLS protocol, just to keep our checks quiet
    );
    foreach my $rex (@insecure) {               # remove all known insecure suites
        _trace2("sort_names: insecure regex\t= $rex }");
        push(@latest, grep{ /$rex/} @ciphers);  # add matches to result
        @ciphers    = grep{!/$rex/} @ciphers;   # remove matches from original list
    }
    foreach my $rex (@strength) {               # sort according strength
        $rex = qr/^(?:(?:SSL|TLS)[_-])?$rex/;   # allow IANA constant names too
        _trace2("sort_names(): regex\t= $rex }");
        push(@sorted, grep{ /$rex/} @ciphers);  # add matches to result
        @ciphers    = grep{!/$rex/} @ciphers;   # remove matches from original list
    }
    # TODO: @ciphers should now be empty, check ...
    push(@sorted, @latest);                     # add insecure ciphers again
    my $cnt_out = scalar @sorted;
    if ($cnt_in != $cnt_out) {
        # print warning if above algorithm misses ciphers;
        # uses Perl's warn() instead of our OCfg::warn() to clearly inform the
        # user that the code here needs to be fixed
        my @miss;
        for my $i (0..$#ciphers) {
            push(@miss, $ciphers[$i]) unless grep {$_ eq $ciphers[$i]} @sorted;
        }
        @miss = sort @miss; # SEE Note:Testing, sort
        warn $STR{WARN}, "412: missing ciphers in sorted list ($cnt_out < $cnt_in): @miss"; ## no critic qw(ErrorHandling::RequireCarping)
    }
    @sorted = grep{!/^\s*$/} @sorted;           # remove empty names, if any ...
    _trace("sort_names(){ $cnt_out ciphers\t= @sorted }");
    return @sorted;
} # sort_names

sub sort_results    {   ## no critic qw(Subroutines::ProhibitExcessComplexity)
    #? sort array of ciphers according their strength
    # returns array with sorted cipher keys
    # only used when ckecking for ciphers with openssl
#TODO: should be same as sort_names()
    my $unsorted= shift;    # hash with $key => yes-or-no
    my @sorted;             # array to be returned
    my @tmp_arr;
    foreach my $key (sort keys %$unsorted) {
        next if ($key =~ m/^\s*$/);     # SEE Note:Defensive Programming
        my $cipher    = get_name($key);
        if (not defined $cipher) {      # SEE Note:Defensive Programming
            OCfg::warn("862: unknown cipher key '$key'; key ignored");
            next;
        }
        my $sec_osaft = lc(get_sec($key));# lower case
        my $sec_owasp = OCfg::get_cipher_owasp($cipher);
           $sec_owasp = "N/A" if ('-?-' eq $sec_owasp); # sort at end
        # Idea about sorting according severity/security risk of a cipher:
        #   * sort first according OWASP rating A, B, C
        #   then use a weight for each cipher:
        #   * most secure cipher first
        #   * prefer ECDHE over DHE over ECDH
        #   * prefer SHA384 over /SHA256 over SHA
        #   * prefer CHACHA over AES
        #   * prefer AES265 over AES128
        #   * sort any anon (ADH, DHA, ..) and EXPort at end
        #   * NULL is last
        # then use OpenSSL/O-Saft rating, hence the string to be sorted looks
        # like:
        #       # A 20 high ...
        #       # A 23 high ...
        #       # B 33 high ...
        #       # B 37 medium ...
        # One line in incomming array in @unsorted:
        #       # TLSv12, ECDHE-RSA-AES128-GCM-SHA256, yes
        # will be converted to following line:
        #       # A 20 HIGH ECDHE-RSA-AES128-GCM-SHA256 TLSv12 yes
        my $weight = 50; # default if nothing below matches
        $weight  = 19 if ($cipher =~ /^ECDHE/i);
        $weight  = 25 if ($cipher =~ /^ECDHE.ECDS/i);
        $weight  = 29 if ($cipher =~ /^(?:DHE|EDH)/i);
        $weight  = 39 if ($cipher =~ /^ECDH[_-]/i);
        $weight  = 59 if ($cipher =~ /^(?:DES|RC)/i);
        $weight  = 69 if ($cipher =~ /^EXP/i);
        $weight  = 89 if ($cipher =~ /^A/i);        # NOTE: must be before ^AEC
        $weight  = 79 if ($cipher =~ /^AEC/i);      # NOTE: must be after ^A
        $weight  = 99 if ($cipher =~ /^NULL/i);
        $weight -= 11 if ($cipher =~ /^TLS[_-]/);   # some TLSv1.3 start with TLS_*
        $weight -= 10 if ($cipher =~ /^TLS13[_-]/); # some TLSv1.3 start or TLS13_*
        $weight -= 9  if ($cipher =~ /SHA512$/);
        $weight -= 8  if ($cipher =~ /SHA384$/);
        $weight -= 7  if ($cipher =~ /SHA256$/);
        $weight -= 6  if ($cipher =~ /SHA128$/);
        $weight -= 5  if ($cipher =~ /256.SHA$/);
        $weight -= 4  if ($cipher =~ /128.SHA$/);
        $weight -= 3  if ($cipher =~ /CHACHA/);
        $weight -= 2  if ($cipher =~ /256.GCM/);
        $weight -= 1  if ($cipher =~ /128.GCM/);
        # TODO: need to "rate"  -CBC- and -RC4- and -DSS-
        push(@tmp_arr, "$sec_owasp.$weight $key ");
           # single word for "$sec_owasp.$weight",
           # otherwise sort is not guaranteed to return always same oder
    }
    foreach my $line (sort @tmp_arr) {  # sorts according $sec_owasp
        my @arr = split(" ", $line);
        push(@sorted, $arr[1]);
    }
    return @sorted;
} # sort_results

=pod

=head3 is_typ($type, $key)

Returns cipher's suite name for cipher of given key if any of the cipher suite
names or constant names matches the specified type.
Key can be the  cipher's hex key, suite name or constant name.
Type can be a Perl regular expression, any key defined in  "$cfg{'regex'}", or
any of following constants:

=over

=item * "ADH"   - uses "$cfg{'regex'}->{'ADHorDHA'}"

=item * "EDH"   - uses "$cfg{'regex'}->{'DHEorEDH'}"

=item * "EXP"   - uses "$cfg{'regex'}->{'EXPORT'}"

=item * "FRZ"   - uses "$cfg{'regex'}->{'FRZorFZA'}"

=item * "RC4"   - uses "$cfg{'regex'}->{'RC4orARC4'}"

=back

=cut

sub is_typ      {
    #? return cipher suite name if $cipher is of $typ, empty string otherwise
    #? checks names and constants; returns primary name even if key was given
    my $rex     = shift;# can be RegEx or string constant
    my $key     = shift;# can be key, name or constant; pattern not supported
    my $cipher  = "";
    SWITCH: {
        last if (ref($rex) =~ /^Regexp/i);  # nothing to do
        if (defined $OCfg::cfg{'regex'}->{$rex}) {
             # known RegEx
             $rex = $OCfg::cfg{'regex'}->{$rex};
             last;
        }
        # constants which are an alias for known RegEx
        if ('ADH' eq $rex) { $rex = $OCfg::cfg{'regex'}->{'ADHorDHA'};  last; }
        if ('EDH' eq $rex) { $rex = $OCfg::cfg{'regex'}->{'DHEorEDH'};  last; }
        if ('EXP' eq $rex) { $rex = $OCfg::cfg{'regex'}->{'EXPORT'};    last; }
        if ('FRZ' eq $rex) { $rex = $OCfg::cfg{'regex'}->{'FRZorFZA'};  last; }
        if ('RC4' eq $rex) { $rex = $OCfg::cfg{'regex'}->{'RC4orARC4'}; last; }
        # DEFAULT: build RegEx from string
        $rex = qr($rex);
    } # SWITCH:
    #_dbx "typ=$typ -> rex=$rex";
    if (not is_valid_key($key)) {
       $key = get_key($key); # is_valid_key() printed warning, if invalid key
    }
    $cipher = get_name($key) if (grep{/$rex/} get_consts($key), get_names($key));
    return $cipher;
} # is_typ


#_____________________________________________________________________________
#____________________________________________________ internal test methods __|

=pod

=head2 Methods intended for inernal use

=head3 show_getter03

Show hardcoded example for all getter functions for key 0x03000003 (aka 0x00,0x03).

=head3 show_getter($cipher_key)

Show example for all getter functions for specified cipher key.

=head3 show_description

Show textual description for columns %ciphers hash.

=head3 show_sorted

Show %ciphers sorted according strength.

=head3 show_overview

Show overview of internal checks about %ciphers.

=head3 show_all_names($type)

Show aliases, constants or RFCs for cipher suite names depending on $type.

=head3 show_ssltest

Show internal list of ciphers in format like ssltest.

=head3 show_ciphers($type)

Show internal list of ciphers in specified format.

=cut

sub show_getter03   {
    #? show hardcoded example for all getter functions for key 0x03000003 (aka 0x00,0x03)
    _v_print((caller(0))[3]);
#   0x00,0x03	RSA  40   N    RC4  RSA(512) MD5  4346,6347  0    WEAK SSLv3  export
#   0x00,0x03   EXP-RC4-MD5    RSA_RC4_40_MD5
# C,0x00,0x03   RSA_EXPORT_WITH_RC4_40_MD5

    my $cipher = "0x00,0x03";       # 0x03000003
    $cipher = text2key("0x00,0x03");# normalize cipher key
    printf("# testing example: $cipher (aka 0x00,0x03) ...\n");
    printf("# %s(%s)\t%s\t%-14s\t# %s\n", "function", "cipher key", "key", "value", "(expected)");
    printf("#----------------------+-------+----------------+---------------\n");
    #printf("%-10s(%s)\t%s\t%-14s\t# %s\n", "get_dtls",  $cipher, "dtls", get_dtls( $cipher), "N");
    printf("%-10s(%s)\t%s\t%-14s\t# %s\n", "get_bits",  $cipher, "bits", get_bits( $cipher), "40");
    printf("%-10s(%s)\t%s\t%-14s\t# %s\n", "get_enc",   $cipher, "enc",  get_enc(  $cipher), "RC4");
    printf("%-10s(%s)\t%s\t%-14s\t# %s\n", "get_keyx",  $cipher, "keyx", get_keyx( $cipher), "RSA(512)");
    printf("%-10s(%s)\t%s\t%-14s\t# %s\n", "get_auth",  $cipher, "auth", get_auth( $cipher), "RSA");
    printf("%-10s(%s)\t%s\t%-14s\t# %s\n", "get_mac",   $cipher, "mac",  get_mac(  $cipher), "MD5");
    printf("%-10s(%s)\t%s\t%-14s\t# %s\n", "get_rfc",   $cipher, "rfc",  get_rfc(  $cipher), "4346,6347");
    printf("%-10s(%s)\t%s\t%-14s\t# %s\n", "get_sec",   $cipher, "sec",  get_sec(  $cipher), "WEAK");
    printf("%-10s(%s)\t%s\t%-14s\t# %s\n", "get_ssl",   $cipher, "ssl",  get_ssl(  $cipher), "SSLv3");
    printf("%-10s(%s)\t%s\t%-14s\t# %s\n", "get_name",  $cipher, "name", get_name( $cipher), "EXP-RC4-MD5");
    printf("%-10s(%s)\t%s\t%-14s\t# %s\n", "get_names", $cipher, "names",   scalar(get_names($cipher)), "EXP-RC4-MD5");
    printf("%-10s(%s)\t%s\t%-14s\t# %s\n", "get_aliases", $cipher,"aliases",scalar(get_aliases($cipher))||"", "");
    printf("%-10s(%s)\t%s\t%-14s\t# %s\n", "get_const", $cipher, "const",get_const($cipher), "RSA_WITH_RC4_40_MD5");
    printf("%-10s(%s)\t%s\t%-14s\t# %s\n", "get_consts",$cipher, "consts",  scalar(get_consts($cipher)), "RSA_WITH_RC4_40_MD5 RSA_RC4_40_MD5 RSA_EXPORT_WITH_RC4_40_MD5 RC4_128_EXPORT40_WITH_MD5");
    printf("%-10s(%s)\t%s\t%-14s\t# %s\n", "get_note",  $cipher, "note", get_note( $cipher), "EXPORT");
    printf("%-10s(%s)\t%s\t%-14s\t# %s\n", "get_notes", $cipher, "notes",get_notes($cipher), "EXPORT");
    printf("%-10s(%s)\t%s\t%-14s\t# %s\n", "get_iana",  $cipher, "iana", get_iana( $cipher), "no");
    printf("%-10s(%s)\t%s\t%-14s\t# %s\n", "get_pfs",   $cipher, "pfs",  get_iana( $cipher), "no");
    printf("%-10s(%s)\t%s\t%-14s\t# %s\n", "get_encsize",$cipher,"encsize", get_encsize( $cipher), "-");
    printf("%-10s(%s)\t%s\t%-14s\t# %s\n", "get_data",  $cipher, "data", get_data( $cipher), "WEAK WEAK SSLv3 RSA(512) RSA RC4 40 MD5 4346,6347 EXP-RC4-MD5 RSA_WITH_RC4_40_MD5,RSA_RC4_40_MD5,RSA_EXPORT_WITH_RC4_40_MD5,RC4_128_EXPORT40_WITH_MD5 export");
    printf("#----------------------+-------+----------------+---------------\n");
    return;
} # show_getter03

sub show_getter     {
    #? show example for all getter functions for specified cipher key
    my $key = shift;
    _v_print((caller(0))[3]);
    if ($key !~ m/^[x0-9a-fA-F,]+$/) {   # no cipher given, print hardcoded example
        printf("# unknown cipher key '$key'; using hardcoded default instead\n");
        show_getter03;
        return;
    }
    print "= testing: $key ...\n";
    $key = text2key($key);    # normalize cipher key
    if (not defined $ciphers{$key}) {
        OCfg::warn("511: undefined cipher '$key'");
        return;
    }
    printf("= %s(%s)\t%s\t%s\n", "function", "cipher key", "key", "value");
    printf("=----------------------+-------+----------------\n");
    #printf("%-10s(%s)\t%s\t%s\n", "get_dtls",  $key, "dtls",  get_dtls( $key) );
    printf("%-10s(%s)\t%s\t%s\n", "get_bits",  $key, "bits",  get_bits( $key) );
    printf("%-10s(%s)\t%s\t%s\n", "get_enc",   $key, "enc",   get_enc(  $key) );
    printf("%-10s(%s)\t%s\t%s\n", "get_keyx",  $key, "keyx",  get_keyx( $key) );
    printf("%-10s(%s)\t%s\t%s\n", "get_auth",  $key, "auth",  get_auth( $key) );
    printf("%-10s(%s)\t%s\t%s\n", "get_mac",   $key, "mac",   get_mac(  $key) );
    printf("%-10s(%s)\t%s\t%s\n", "get_rfc",   $key, "rfc",   get_rfc(  $key) );
    printf("%-10s(%s)\t%s\t%s\n", "get_sec",   $key, "sec",   get_sec(  $key) );
    printf("%-10s(%s)\t%s\t%s\n", "get_ssl",   $key, "ssl",   get_ssl(  $key) );
    printf("%-10s(%s)\t%s\t%s\n", "get_name",  $key, "name",  get_name( $key) );
    printf("%-10s(%s)\t%s\t%s\n", "get_names", $key, "names", join(" ", get_names($key)) );
    printf("%-10s(%s)\t%s\t%s\n", "get_aliases", $key, "aliases", join(" ", get_aliases($key)) );
    printf("%-10s(%s)\t%s\t%s\n", "get_const", $key, "const", get_const($key) );
    printf("%-10s(%s)\t%s\t%s\n", "get_consts", $key, "consts",   join(" ", get_consts($key)) );
    printf("%-10s(%s)\t%s\t%s\n", "get_note",  $key, "note",  get_note( $key) );
    printf("%-10s(%s)\t%s\t%s\n", "get_notes", $key, "notes", join("", get_notes($key)) );
    printf("%-10s(%s)\t%s\t%s\n", "get_iana",  $key, "iana",  get_iana( $key) );
    printf("%-10s(%s)\t%s\t%s\n", "get_pfs",   $key, "pfs",   get_iana( $key) );
    printf("%-10s(%s)\t%s\t%s\n", "get_encsize",$key, "encsize", get_encsize( $key) );
    printf("%-10s(%s)\t%s\t%s\n", "get_data",  $key, "data",  get_data( $key) );
    printf("=----------------------+-------+----------------\n");
    return;
} # show_getter

sub show_description {
    #? print textual description for columns %ciphers hash
    _v_print((caller(0))[3]);
    local $\ = "\n";
    print << 'EoT';

=== internal data structure: overview of %ciphers ===
EoT

    my $hex = '0x0300003D'; # our sample
    my $idx = 0;
    print ("= %ciphers : example line:\n");
    # we should get the example $ciphers_desc{sample}
    printf("  '$hex' -> ["); # TODO 0x00,0x3D
    foreach (@{$ciphers_desc{head}}) {
        printf("\t%s", $ciphers_desc{sample}->{$hex}[$idx]);
        $idx++;
    }
    print (" ]");
    print ("\n= %ciphers : tabular description of above (example) line:\n");
    print ("=-------+--------------+-----------------------+--------");
    printf("= [%s]\t%15s\t%16s\t%s\n", "nr", "key", "description", "example");
    print ("=-------+--------------+-----------------------+--------");
    $idx = 0;
    foreach (@{$ciphers_desc{head}}) {
        my $txt = $ciphers_desc{$ciphers_desc{head}[$idx]}; # quick dirty
        printf("  [%s]\t%15s\t%-20s\t%s\n", $idx, $ciphers_desc{head}[$idx],
            $txt, $ciphers_desc{sample}->{$hex}[$idx]);
        $idx++;
    }
    printf("=-------+--------------+-----------------------+--------");

    print ("\n\n= %ciphers : description of one line as Perl code:\n");
    print ("=------+------------------------------------+---------------+---------------");
    printf("= varname  %-23s\t# example result# description\n", "%ciphers hash");
    print ("=------+------------------------------------+---------------+---------------");
    $idx = 0;
    foreach my $col (@{$ciphers_desc{head}}) {
        my $var = $ciphers_desc{head}[$idx];    # quick dirty
        my $txt = $ciphers_desc{$var};
	my $tab = (6 > length($col)) ? "\t    " : " "; # dirty hack for pretty printing
        printf("%6s = \$ciphers{'%s'}{%s};$tab# %-7s\t# %s\n",
            '$' . $var, $hex, $col, $ciphers_desc{sample}->{$hex}[$idx], $txt);
        $idx++;
    }
    printf("%6s = \$ciphers{'%s'}{%s}[0];  # %-7s\t# %s\n",
            '$' . 'name', $hex, 'names', 'AES256-SHA256', $ciphers_desc{'name'});
    printf("%6s = \$ciphers{'%s'}{%s}[1];  # %-7s\t# %s\n",
            '$' . 'alias', $hex, 'alias', 'Alias', "first alias");
    print ("=------+------------------------------------+---------------+---------------");

    print  "\n= \%cipher_results : description of hash:\n";
    print  $cipher_results_desc;
    print  "= \%cipher_results : description of Perl code:\n";
    print ("=-------------------------------------------+---------------");
    print ("=           %hash{  ssl   }->{'cipher key'} = [values];");
    print ("=-------------------------------------------+---------------");
    print ("  %cipher_results{'TLSv12'}->{'0x0300003D'} = ['yes', ''];"); # AES256-SHA256
    print ("  %cipher_results{'SSLv3'} ->{'0x02FF0810'} = ['no',  ''];"); # NULL-NULL
    print ("=-------------------------------------------+---------------");

    return;
} # show_description

sub show_sorted     {
    #? print %ciphers sorted according strength
    _v_print((caller(0))[3]);
    local $\ = "\n";
    my $head = "= OWASP openssl self    IANA    cipher suite";
    my $line = "=------+-------+-------+-------+----------------------------------------------";
    print << 'EoT';

=== internal data structure: ciphers sorted according strength ===
=
= Show overview of all available ciphers sorted according OWASP scoring.
=
=   description of columns:
=       OWASP       - OWASP scoring (A, B, C, D)
=       openssl     - strength given bei OpenSSL
=       self        - strength according own rules
=       IANA        - "yes" if recommended by IANA
=       cipher suite- OpenSSL suite name
EoT
    print ($line);
    print ($head);
    print ($line);
    my @sorted;
    my @unsorted;
    push(@unsorted, get_name($_)) foreach sort keys %ciphers;
    foreach my $c (sort_names(@unsorted)) {
        my $key = get_key($c);
        push(@sorted, sprintf("%4s\t%s\t%s\t%s\t%s",
                               OCfg::get_cipher_owasp($c), get_openssl($key),
                               get_sec($key), get_iana($key), $c
            ));
    }
    print foreach sort @sorted;
    print ($line);
    print ($head);
    printf("=\n");
    printf("= %4s sorted ciphers\n",  scalar @sorted);
    printf("= %4s ignored ciphers\n", ((keys %ciphers) - (scalar @sorted)));
    return;
} # show_sorted

sub show_overview   {
    #? print overview of internal checks about %ciphers
    _v_print((caller(0))[3]);
    local $\ = "\n";
    print << 'EoT';

=== internal data structure: information about ciphers ===
=
= This function prints a simple overview of all available ciphers. The purpose
= is to show if the internal data structure provides all necessary data.
=
=   description of columns:
=       key         - hex key for cipher suite
=       security    - cipher suite security is known
=       name        - cipher suite (OpenSSL) name exists
=       aliases     - cipher suite has other kown cipher suite names
=       const       - cipher suite constant name exists
=       cipher suite- cipher suite name (OpenSSL)
=   description of values:
=       *    value present (also if None or for pseudo ciphers)
=       -    value missing
=       -?-  security unknown/undefined
=       miss security missing in data structure
=
= No Perl or other warnings should be printed.
= Note: following columns should have a  *  in columns
=       security, name, const
EoT

    my $line = sprintf("=%s+%s+%s+%s+%s+%s", "-" x 14, "-"x 7, "-" x 7, "-" x 7, "-" x 7, "-" x 21);
    my $head = sprintf("= %-13s%s\t%s\t%s\t%s\t%s", "key", "security", "name", "aliases", "const", "cipher suite");
    print($line);
    print($head);
    print($line);
    my %err;    # count incomplete settings
    my $cnt = 0;
    foreach my $key (sort keys %ciphers) {
         $cnt++;
         my $sec    = $ciphers{$key}->{'sec'};
         my $name   = "-";
         my $alias  = "-";
         my $const  = "-";
         my $cipher = $ciphers{$key}->{'names'}[0];
         # TODO: compare direct access of %cipher* with results of method get_*
         $sec   = "*" if ($sec =~ m/None|weak|low|medium|high/i); # TODO: $cfg{'regex'}->{'security'}/i);
         $sec   = "-" if ($sec ne "*" and $sec ne "-?-"); # anything else is -
         $name  = "*" if $ciphers{$key}->{'names'}[0] ne "";
         $alias = "*" if $ciphers{$key}->{'names'}    ne "-";
         $const = "*" if $ciphers{$key}->{'const'}[0] ne "";
         printf("%12s\t%s\t%s\t%s\t%s\t%s\n", $key, $sec, $name, $alias, $const, $cipher);
         $err{'security'}++ if ('*' ne $sec );
         $err{'name'}++     if ('*' ne $name);
         $err{'const'}++    if ('*' ne $const);
         $err{'aliases'}++  if ('*' ne $alias);
    }
    print($line);
    print($head);
    printf("=\n= %s ciphers\n", $cnt);
    printf("= identified errors: ");
    printf("%6s=%-2s,", $_, $err{$_}) foreach sort keys %err;
    printf("\n");
    return;
} # show_overview

sub show_all_names  {
    #? show aliases, constants or RFCs for cipher suite names depending on $type
    #  $type: name | const | rfc
    ## no critic qw(ValuesAndExpressions::ProhibitImplicitNewlines)
    my $type = shift;
    _v_print((caller(0))[3]);
    my $text = $type;
       $text = "name"     if $type =~ /names/;  # lazy check
       $text = "constant" if $type =~ /const/;  # lazy check
       $text = "RFC"      if $type =~ /rfc/;    #
    my $txt_cols = 
"=       cipher name - (most common) cipher suite $text
=       alias names - known aliases for cipher suite $text";
       $txt_cols =
"=       cipher name - cipher suite name as used in openssl
=       RFC         - RFC numbers, where cipher suite is described" if ("rfc" eq $type);
    local $\ = "\n";
    print <<"EoT";

=== internal data structure: overview of various cipher suite ${text}s ===
=
=   description of columns:
=       key         - hex key for cipher suite
$txt_cols
EoT
    my $line = sprintf("=%s+%s+%s\n", "-" x 14, "-" x 39, "-" x 31);
    printf("$line");
    printf("= %-13s\t%-37s\t%s\n", "key", "cipher name", "$text  names");
    printf("$line");
    foreach my $key (sort keys %ciphers) {
        my @names   = [];
        my $name    = "";
        if ('rfc' eq $type) {
            $name   = $ciphers{$key}->{'names'}[0];
            my $rfc = $ciphers{$key}->{'rfc'};
            next if "-" eq $rfc;
            @names  = $rfc;
        } else {
            @names  = @{$ciphers{$key}->{$type}};
            $name   = shift @names;
            next if 1 > scalar @names;
        }
        printf("%s\t%-37s\t@names\n", $key, $name);
    }
    printf("$line");
    printf("= %-13s\t%-37s\t%s\n", "key", "cipher name", "alias names");
    return;
} # show_all_names

sub show_ssltest    {
    #? print internal list of ciphers in format like ssltest
    # %ciphers are sorted by protocol and name  # SEE Note:Testing, sort
    _v_print((caller(0))[3]);
    my $last_k  = "";
    foreach my $key (sort { $ciphers{$a}->{ssl}   cmp $ciphers{$b}->{ssl} ||
                            $ciphers{$a}->{names} cmp $ciphers{$b}->{names}
                          } keys %ciphers) {
        # FIXME: sort returns slightly random sequence in continous calls;
        #        reason unknown, probably $ciphers{$a}->{ssl}
        #        this does not impact the functionality, but makes comparing
        #        results more difficult
        if ($last_k ne $ciphers{$key}->{ssl}) {
            $last_k =  $ciphers{$key}->{ssl};
            printf("%s Ciphers Supported...\n", $ciphers{$key}->{ssl});
        }
        my $name    = $ciphers{$key}->{'names'}[0]; # special value
        my $auth =  $ciphers{$key}->{auth};
           $auth =  "No" if ($auth =~ /none/i);
        my $keyx =  $ciphers{$key}->{keyx};
           $keyx =~ s/[()]//g;
        my $bits =  $ciphers{$key}->{bits};
        if ($bits =~ m/\d+/) {
           $bits =  sprintf("%03d", $ciphers{$key}->{bits});
        } else {
           $bits =  "-?-";
           $bits =  "000" if ($ciphers{$key}->{enc} =~ m/None/i);
        }
#   NULL-MD5, None 000 bits, No Auth, MD5 MAC, RSA512 Kx
        printf("   %s, %s %s bits, %s Auth, %s MAC, %s Kx\n", $name,
                $ciphers{$key}->{enc}, $bits, $auth, $ciphers{$key}->{mac}, $keyx);
    }
    return;
} # show_ssltest

sub show_ciphers    {   ## no critic qw(Subroutines::ProhibitExcessComplexity)
    #? print internal list of ciphers in specified format
    my $format = shift;
    _v_print((caller(0))[3]);
    local $\ = "\n";
    if ($format !~ m/(?:dump|full|osaft|openssl|simple|show)/) {
        OCfg::warn("520: unknown format '$format'");
        return;
    }

    my $out_header  = 1;
    my $txt_head    = "";
    if ($format eq "openssl") { # like 'openssl ciphers'
        print join(":", get_names_list());
        return;
    }
    if ($format =~ m/openssl/) {
        print << "EoT";
= Output is similar (order of columns) but not identical to result of
= 'openssl ciphers -[vV]' command.
EoT
        $out_header = 0;
        $txt_head   = "";
    } else {
        my $idx = 0;
        foreach (@{$ciphers_desc{head}}) {  # build description from %ciphers_desc
            my $txt = $ciphers_desc{$ciphers_desc{head}[$idx]}; # quick dirty
            $txt_head .= sprintf("=      %-12s - %s\n", $ciphers_desc{head}[$idx], $txt);
            $idx++;
        }
    }

    my @columns = @{$ciphers_desc{head}}; # cannot be used because we want specific order
    @columns = qw(openssl sec ssl keyx auth enc bits mac rfc names const notes) if ($format =~ m/^(?:dump|full|osaft)/);
    @columns = qw(ssl keyx auth enc bits mac)     if ($format =~ m/^(?:openssl)/);
    @columns = qw(ssl keyx auth enc bits mac sec) if ($format =~ m/^(?:show)/);
    @columns = qw(sec ssl keyx auth enc bits mac) if ($format =~ m/^(?:simple)/);

    # table head
    my $line    = sprintf("=%s\n", "-" x 77 );
    my $head    = "";
    if ($format =~ m/^(?:dump|full|osaft)/) {
# 0x02000000    weak   SSLv2   RSA(512) RSA    None    Mac     -?-     NULL-MD5 NULL_WITH_MD5 -
        $line = sprintf("=%9s%s%s\n", "-" x 14, "+-------" x 9, "+---------------" x 3 );
        $head = sprintf("= %-13s\t%9s\n", "key",    join("\t", @columns));
    }
    if ($format =~ m/^(?:show)/) {
# 0x02000000    SSLv2   RSA(512) RSA    None   0       Mac     weak     NULL-MD5
        $line = sprintf("=%s%s+%s\n", "-" x 14, "+-------" x 7, "-" x 15 );
        $head = sprintf("= %-13s\t%s\t%s\n", "key", join("\t", @columns), "cipher name");
    }
    if ($format =~ m/^(?:simple)/) {
# 0x02000000    weak SSLv2 RSA(512) RSA None 0 Mac NULL-MD5
        # no fomated header just a line
        $head = sprintf("= %-13s\t%s\t%s\n", "key", join(" ",  @columns), "cipher name");
    }
    if ($format =~ m/^openssl-V/) {
#         0x00,0x3D - AES256-SHA256           TLSv1.2 Kx=RSA      Au=RSA  Enc=AES(256)  Mac=SHA256
#    0x00,0x00,0x00 - NULL-MD5                SSLv2   Kx=RSA(512) Au=RSA  Enc=None(0)   Mac
        $line = sprintf("=%s+%s+%s+%s+%s+%s+%s\n",
               "-" x 19, "-" x 24, "-" x 5, "-" x 11, "-" x 7, "-" x 11, "-" x 7 );
        $head = sprintf("=% 18s - %-23s %-5s %-11s %-7s %-11s %s\n",
               "key", "name", @columns[0..2], "enc(bit)", "mac");
    }
    if (0 < $out_header) {
        printf("%s", << "EoT"); # printf to avoid trailing \n

=== internal %ciphers data ===
=
= Show a full overview of all available ciphers.
=
=   description of columns (if available):
=      key          - internal hex key for cipher suite
=      hex          - hex key for cipher suite (like openssl)
=      cipher name  - OpenSSL suite name
$txt_head
EoT
       printf($line);
       printf($head);
       printf($line);
    }

    # table data (format should be same as for table head above)
    my $cnt = 0;
    foreach my $key (sort keys %ciphers) {
        $cnt++;
        my $hex     = key2text($key);   # 0x02010080 --> 0x01,0x00,0x80
        my $name    = $ciphers{$key}->{'names'}[0]; # special value
        my $const   = $ciphers{$key}->{'const'}[0]; # special value
        my $note    = $ciphers{$key}->{'notes'}[0]; # special value
        my @values;
        if ($format =~ m/^(?:dump|full|osaft)/) {
            push(@values, $key);
            push(@values, $ciphers{$key}->{$_}) foreach @columns[0..8];
           #push(@values, join(",", @{$ciphers{$key}->{$_}})) foreach @columns[9..11];
            push(@values, join(",", @{$ciphers{$key}->{names}}));
            push(@values, join(",", @{$ciphers{$key}->{const}}));
            push(@values, join(",", @{$ciphers{$key}->{notes}}));
            printf("%s\n", join("\t", @values));
        }
        if ($format =~ m/^(?:show)/) {
            push(@values, $key);
            push(@values, $ciphers{$key}->{$_}) foreach @columns;
            push(@values, $name);
            printf("%s\n", join("\t", @values));
        }
        if ($format =~ m/^(?:simple)/) {
            push(@values, $ciphers{$key}->{$_}) foreach @columns;
            push(@values, $name);
            printf("%s\t%s\n", $key, join(" ", @values));
        }
        if ($format =~ m/^(?:openssl-v)/) {
            push(@values, $name);
            push(@values, $ciphers{$key}->{$_}) foreach @columns;
            printf("%-23s %-6s Kx=%-8s Au=%-4s Enc=%s(%s) Mac=%s\n", @values);
        }
        if ($format =~ m/^(?:openssl-V)/) {
            push(@values, $hex, $name);
            push(@values, $ciphers{$key}->{$_}) foreach @columns;
            printf("%19s - %-23s %-6s Kx=%-8s Au=%-4s Enc=%s(%s) Mac=%s\n", @values);
        }
    } # keys

    # table footer
    if (0 < $out_header) {
        printf($line);
        printf($head);
        printf("=\n= %s ciphers\n", $cnt);
    }
    return;
} # show_ciphers

sub show            {   ## no critic qw(Subroutines::ProhibitExcessComplexity)
    #? dispatcher for various +test-ciphers-* commands; show information
    my $arg = shift;    # any +test-ciphers-*
       $arg =~ s/^\+?test[._-]?ciphers[._-]?//; # normalize
    _v_print((caller(0))[3]);
    #_dbx("arg=$arg");
    local $\ = "\n";
    print "$VERSION"        if ($arg =~ /version$/i             );
    show_all_names('const') if ($arg =~ m/const(?:ants?)?$/     );
    show_all_names('names') if ($arg =~ m/alias(?:es)?$/        );
    show_all_names('rfc')   if ($arg =~ m/rfcs?$/               );
    show_description()      if ($arg eq 'description'           );
    show_description()      if ($arg =~ m/^ciphers.?description/);
    show_overview()         if ($arg eq 'overview'              );
    show_ssltest()          if ($arg eq 'ssltest'               );
    show_sorted()           if ($arg =~ m/^(owasp|sort(?:ed)?$)/);
    show_ciphers('simple')  if ($arg eq 'list'                  ); # ancient option
        ## no critic qw(RegularExpressions::ProhibitCaptureWithoutTest)
    show_ciphers($1)        if ($arg =~ m/^(show|simple)$/      );
    show_ciphers($1)        if ($arg =~ m/^(dump|full|osaft|openssl(?:-[vV])?)$/);
    show_getter($1)         if ($arg =~ m/^getter=?(.*)/        );
    print is_typ('ADH',$1)  if ($arg =~ m/^is.?adh=(.*)/        );
    print is_typ('CBC',$1)  if ($arg =~ m/^is.?cbc=(.*)/        );
    print is_typ('DES',$1)  if ($arg =~ m/^is.?des=(.*)/        );
    print is_typ('EDH',$1)  if ($arg =~ m/^is.?edh=(.*)/        );
    print is_typ('EXP',$1)  if ($arg =~ m/^is.?exp=(.*)/        );
    print is_typ('FRZ',$1)  if ($arg =~ m/^is.?frz=(.*)/        );
    print is_typ('RC4',$1)  if ($arg =~ m/^is.?rc4=(.*)/        );
    print "** please use any of: is_adh, is_cbc, is_des, is_edh, is_exp, is_frz, is_rc4"
                            if ($arg =~ m/^is.?typ=(.*)/        );
    print is_valid_key($1)  if ($arg =~ m/^is.?valid.?key=(.*)/ );
    print text2key($1)      if ($arg =~ m/^text2key=(.*)/       );
    print key2text($1)      if ($arg =~ m/^key2text=(.*)/       );
    print get_key($1)       if ($arg =~ m/^(?:get.)?key=(.*)/   );
    print get_sec($1)       if ($arg =~ m/^(?:get.)?sec=(.*)/   );
    print get_ssl($1)       if ($arg =~ m/^(?:get.)?ssl=(.*)/   );
    print get_keyx($1)      if ($arg =~ m/^(?:get.)?keyx=(.*)/  );
    print get_auth($1)      if ($arg =~ m/^(?:get.)?auth=(.*)/  );
    print get_enc($1)       if ($arg =~ m/^(?:get.)?enc=(.*)/   );
    print get_bits($1)      if ($arg =~ m/^(?:get.)?bits=(.*)/  );
    print get_mac($1)       if ($arg =~ m/^(?:get.)?mac=(.*)/   );
    print get_rfc($1)       if ($arg =~ m/^(?:get.)?rfc=(.*)/   );
    print get_name($1)      if ($arg =~ m/^(?:get.)?name=(.*)/  );
    print get_const($1)     if ($arg =~ m/^(?:get.)?const=(.*)/ );
    print get_note($1)      if ($arg =~ m/^(?:get.)?note=(.*)/  );
    print get_openssl($1)   if ($arg =~ m/^(?:get.)?openssl=(.*)/);
    print get_encsize($1)   if ($arg =~ m/^(?:get.)?encsize=(.*)/);
    print get_iana($1)      if ($arg =~ m/^(?:get.)?iana=(.*)/  );
    print get_pfs($1)       if ($arg =~ m/^(?:get.)?pfs=(.*)/   );
    print find_name($1)     if ($arg =~ m/^find.?name=(.*)/     );
    # enforce string value for returned arrays
    print join(" ", find_names_any($1)) if ($arg =~ m/^find.?names.?any=(.*)/);
    print join(" ", find_keys_any($1))  if ($arg =~ m/^find.?keys.?any=(.*)/ );
    print join(" ", find_names($1))     if ($arg =~ m/^find.?names=(.*)/     );
    print join(" ", find_keys($1))      if ($arg =~ m/^find.?keys=(.*)/      );
    print join(" ", find_consts($1))    if ($arg =~ m/^find.?consts=(.*)/    );
    print join(" ", get_names($1))      if ($arg =~ m/^(?:get.?)?names=(.*)/  );
    print join(" ", get_aliases($1))    if ($arg =~ m/^(?:get.?)?aliases=(.*)/);
    print join(" ", get_consts($1))     if ($arg =~ m/^(?:get.?)?consts=(.*)/ );
    print join(" ", get_notes($1))      if ($arg =~ m/^(?:get.?)?notes=(.*)/  );
    print join(" ", get_keys_list())    if ($arg =~ m/^(?:get.?)?keys.?list$/ );
    print join(" ", get_names_list())   if ($arg =~ m/^(?:get.?)?names.?list$/);
    if ($arg =~ m/^regex/) {
        printf("#$0: direct testing not yet possible here, please try:\n   o-saft.pl +test-ciphers-regex\n");
    }
    return;
} # show

#_____________________________________________________________________________
#___________________________________________________ initialisation methods __|

sub _ciphers_init   {
    #? initialisations of %cihers data structures from <DATA>
    # example:   #0     #1      #2      #3      #4          #5      #6      #7 ...
    #     0x02020080    WEAK    WEAK    SSLv2   RSA(512)    RSA     RC4     40    MD5    -?-    EXP-RC4-MD5    RC4_128_EXPORT40_WITH_MD5    EXPORT
    my $fh = *DATA;
    my $dumm = *DATA;   # SEE Note:Defensive Programming
    if (0 < $::osaft_standalone) {  # SEE Note:Stand-alone
        ## no critic qw(InputOutput::RequireBriefOpen)
        ## no critic qw(ErrorHandling::RequireCarping)
        open($fh, "<", $0) or warn($OText::STR{ERROR}, "013: open '$0' failed with: $!");
        while (<$fh>) { last if m(^__DATA__); } # skip to definition of ciphers
    }
    while (my $line = <$fh>) {
        chomp $line;
        next if ($line =~ m/^\s*$/);
        next if ($line =~ m/^\s*#/);
        last if ($line =~ m/__END/);
        my @fields = split(/\t/, $line);
        my $len    = $#fields;
        my $key    = $fields[0];
        if ($key  !~ /^0x[0-9A-F]{8}/) {    # cannot use is_valid_key() because some keys have suffixes
            OCfg::warn("504: DATA line" . sprintf("%4d", $.) . ": wrong hex key '$key'");
            next;
        }
        if (13 != $len+1) {
            OCfg::warn("505: DATA line" . sprintf("%4d", $.) . ": wrong number of TAB-separated fields '$len' != 13");
            next;
        }
            # above two messages could be constructed in a simpler way, like:
            #   OCfg::warn(sprintf("504: DATA line%4d: ..text..'", $., $key));
            # because other tools (i.e. make) extract the message, we provide
            # the well known pattern for them:
            #   OCfg::warn("504: DATA line" . sprintf("%4d", $.) . ": ..text.. '$key'");
        # now loop over @fields, but assign each to the hash; keys see %ciphers_desc
        $ciphers{$key}->{'openssl'} = $fields[1]  || '';
        $ciphers{$key}->{'sec'}     = $fields[2]  || '';
        $ciphers{$key}->{'ssl'}     = $fields[3]  || '';
        $ciphers{$key}->{'keyx'}    = $fields[4]  || '';
        $ciphers{$key}->{'auth'}    = $fields[5]  || '';
        $ciphers{$key}->{'enc'}     = $fields[6]  || '';
        $ciphers{$key}->{'bits'}    = ($fields[7] || '0 '); # our values are strings, but perl cast to int, which renders 0 as ''; ugly, very ugly hack
        $ciphers{$key}->{'mac'}     = $fields[8]  || '';
        $ciphers{$key}->{'rfc'}     = $fields[9]  || '';
        @{$ciphers{$key}->{'names'}}= split(/,/, $fields[10]);
        @{$ciphers{$key}->{'const'}}= split(/,/, $fields[11]);
        @{$ciphers{$key}->{'notes'}}= split(/,/, $fields[12]);
       #$ciphers{$key}->{'suite'}   = # is first in $fields[10], 
    }
    push(@{$OCfg::dbx{'files'}}, "lib/Ciphers.pm"); # set myself
    return;
} # _ciphers_init

#_____________________________________________________________________________
#_____________________________________________________________________ main __|

sub _main   {
    #? print own documentation or special required one
    my @argv = @_;
    push(@argv, "--help") if (0 > $#argv);
    my %usage = (
        # texts should be same as or similar to POD's =head1 COMMANDS
        '# commands to show internal cipher tables' => {
            'alias'     => 'alias(es) for cipher suite names',
            'const'     => 'constants for cipher suite names',
            'dump'      => 'all ciphers with internal data',
            'rfc'       => 'RFCs for or related to cipher suite names',
            'overview'  => 'overview of various (internal) checks according ciphers',
            'description' => 'description of all data structures for ciphers',
            'openssl'   => 'all ciphers in format like "openssl ciphers -V"',
            'show'      => 'all ciphers as simple human readable format',
            'simple'    => 'all ciphers as simple space-separated format',
            'sort'      => 'all ciphers sorted according OWASP scoring',
            'ssltest'   => 'all ciphers in format like "ssltest --list"',
        },
        # use alias to pass first argument to 'is_typ()'; for testing only
        "# commands to check cipher type\n# (all following call 'is_typ(TYP,KEY)')" => {
            'is_adh=KEY'  => 'check if cipher is ADH',
            'is_cbc=KEY'  => 'check if cipher is CBC',
            'is_des=KEY'  => 'check if cipher is DES',
            'is_edh=KEY'  => 'check if cipher is EDH',
            'is_exp=KEY'  => 'check if cipher is EXPORT',
            'is_rc4=KEY'  => 'check if cipher is RC4',
        },
        '# commands to show cipher data' => {
            'getter=KEY'        => 'show example for get_*() functions',
            'key=CIPHER-NAME  ' => 'show (internal) cipher key if it is known',
            'is_valid_key=KEY'  => 'show (internal) cipher key if it is known',
        },
        '# commands to show cipher data (various examples)' => {
            'getter=0x0300CCA9' => '',
            'getter=0xCC,0xA9 ' => '',
            'getter=0x03,0x00,0xCC,0xA9'=> '',
            'key=ECDHE-ECDSA-CHACHA20-POLY1305-SHA256' => '',
            'is_valid_key=0300Cca9'     => '',
        },
        "## all commands can also be used as '+test-ciphers-CMD'" => {},
    );
    # got arguments, do something special
    while (my $arg = shift @argv) {
        if ($arg eq '--h')      { print "please use: --usage or --help\n"; exit 0; }
        if ($arg eq '--help')   { OText::print_pod($0, __FILE__, $SID_ciphers); exit 0; }
        if ($arg eq '--usage')  { OText::usage_show("", \%usage); exit 0; }
        # ----------------------------- options
        if ($arg eq '--trace')  { $OCfg::cfg{'trace'}++;   next; }
        if ($arg eq '--v')      { $OCfg::cfg{'verbose'}++; next; }
        # ----------------------------- commands
        if ($arg eq 'version')  { print "$SID_ciphers\n";  next; }
        if ($arg =~ /^[-+]?V(ERSION)?$/){ $arg = "test-ciphers-version"; }
        $arg =~ s/^[+]//;   # allow leading + prefix
        $arg =~ s/^test.?ciphers[_.-]?//; # allow option without prefix +test-ciphers
        show("+test-ciphers$arg");
    }
    exit 0;
} # _main

sub done    {}; # dummy to check successful include

_ciphers_init();

#_____________________________________________________________________________
#_____________________________________________________ public documentation __|

=pod

=head1 COMMANDS

If called from command-line, like

  Ciphers.pm [OPTIONS ..] [COMMANDS]

this modules provides following commands:

=over 4

=item version

- just print the module's version

=item description

- print description of all data structures

=item overview

- print overview of various (internal) checks according cipher definitions

=item aliases

- print overview of known cipher suite names

=item constants

- print overview of known cipher suite constant names

=item rfcs

- print overview of cipher suites and corresponding RFCs

=item dump

- print internal lists of ciphers (all data, internal format)

=item show

- print internal lists of ciphers (simple human readable format)

=item simple

- print internal lists of ciphers (simple space-separated format)

=item sorted

- print internal lists of ciphers (sorted according OWASP scoring)

=item openssl

- print internal lists of ciphers (format like "openssl ciphers -V")

=item ssltest

- print internal lists of ciphers (format like "ssltest --list")

=item getter

- print example for all getter functions for specified cipher key

=item is_typ

- print cipher suite name if specified cipher is of special typ

=back

All commands can be used with or without '+' prefix, for example 'dump' is same
as '+dump'. They can also be used with '+test-ciphers-' perfix, for example:
'+test-ciphers-show'.

The commands  'simple' 'openssl' 'openssl-v' 'openssl-V' and 'ssltest'  are the
same as '+list' command with corresponding '--legacy=' option of "o-saft.pl".

=over 4

=item get_METHOD=HEX

- print cipher suite value for 'METHOD', for valid 'get_METHOD' see  METHODS  above

=item find_keys=CIPHER-SUITE

- print cipher suite internal key for matching cipher names 'CIPHER-SUITE'

=item find_names=CIPHER-SUITE

- print cipher suite names for matching cipher names 'CIPHER-SUITE'

=back


=head1 OPTIONS

=over 4

=item --usage

- print usage for L<COMMANDS> of CLI mode

=item --v

- print verbose messages (in CLI mode only), must precede all commands

=back


=head1 NOTES

It's often recommended not to export constants and variables from modules, see
for example  http://perldoc.perl.org/Exporter.html#Good-Practices . The main
purpose of this module is defining variables. Hence we export them.


=head1 SEE ALSO

# ...


=head1 VERSION

3.67 2025/04/09


=head1 AUTHOR

28-may-16 Achim Hoffmann

=cut

## PACKAGE }

#_____________________________________________________________________________
#_____________________________________________________________________ self __|

_main(@ARGV) if (not defined caller);

1;

# TODO: notes for ciphers (see last column) are missing:
# strange: ECDH_ECDSA_WITH_AES_128_CBC_SHA ECDH_ECDSA_WITH_AES_256_CBC_SHA
# S	DH_anon_WITH_AES_256_GCM_SHA256 is probably a typo found somewhere
# T	used in https://docs.rs/rustls/latest/rustls/enum.CipherSuite.html 07/2024
# T	TLS13_AES* DHE_DSS_EXPORT_WITH_DES40_CBC_SHA ECDH_anon_NULL_WITH_SHA
# T	missing: ECDH_anon_WITH_DES_CBC_SHA, ECDH_anon_EXPORT_WITH_DES40_CBC_SHA ECDH_anon_EXPORT_WITH_RC4_40_SHA
# T	missing: ECDH_ECDSA_WITH_DES_CBC_SHA ECDH_ECNRA_WITH_DES_CBC_SHA ECDH_ECNRA_WITH_3DES_EDE_CBC_SHA
# T	missing: ECMQV_ECDSA_NULL_SHA ECMQV_ECDSA_WITH_RC4_128_SHA ECMQV_ECDSA_WITH_DES_CBC_SHA
# T	missing: ECMQV_ECDSA_WITH_3DES_EDE_CBC_SHA ECMQV_ECNRA_NULL_SHA
# T	missing: ECMQV_ECNRA_WITH_RC4_128_SHA ECMQV_ECNRA_WITH_DES_CBC_SHA ECMQV_ECNRA_WITH_3DES_EDE_CBC_SHA
# T	missing: FORTEZZA_KEA_WITH_RC4_128_SHA is probably FZA-FZA-CBC-SHA
# U     AEDGIS ietf draft lists TLS_AEGIS_256_SHA512, TLS_AEGIS_256_SHA384 may be a typo in older drafts

## CIPHERS {

__DATA__

# Format of following data lines:
#   <empty>     - empty lines are ignored
#   comments    - line beginning with a # (hash); lines are ignored
#   0xhhhhhhhh  - data line containing a cipher suite; used columns are:
#       hex     - hex constant for the cipher suite
#       openssl - security value (STRENGTH) used by openssl
#       sec     - security value used by o-saft.pl
#       ssl     - protocol where the cipher is used (PCT just for information)
#       keyx    - key exchange of the cipher suite (Kx= in openssl)
#       auth    - authenticatione of the cipher suite (Au= in openssl)
#       enc     - encryption of the cipher suite (Enc= in openssl)
#       bits    - bits for encryption of the cipher suite (Enc= in openssl)
#       mac     - Mac of the cipher suite (Mac= in openssl)
#       cipher  - list of known cipher suite names, most common first
#       const   - list of known cipher suite constants, most common first
#       notes   - list of notes and comments
#
#   All columns must be separated by TABs (0x9 aka \t), no spaces are allowed.
#   The left-most word must not be prepended by whitespace characters. It must
#   begin with the cipher suite hex key, like:  0x  followed by exactly  8 hex
#   chars [0-9A-F]. Only such lines are used for ciphers.
#   If additional characters  [a-zA-Z-]  are used in the hex key  it then does
#   not match  ^0x[0-9a-fA-F]{8} . The definition is stored in  %ciphers , but
#   will not be used anywhere (except informational lists).  These definitions
#   are mainly used for documentation, for example ancient cipher definitions.
#   
#   Values in left-most column (the cipher's hex key) must be unique.
#
#   In all other columns, following special strings are used:
#       -       - empty value/string, value not existent, value not applicable
#       -?-     - value currently unknown
#       None    - value not used (as in openssl)
#
#   The fomat/syntax of the table is very strict, because some other tools may
#   use and/or ignore this data.  In particular,  the characters  " [ ] =  are
#   not used to avoid conflicts in other tools (for example Excel).
#
#   This table will be read in _ciphers_init() and converted to %ciphers .

# hex const	openssl	sec	ssl	keyx	auth	enc	bits	mac	rfc	cipher,aliases	const	comment
#--------------+-------+-------+-------+-------+-------+-------+-------+-------+-------+---------------+-------+---------------+
0x03005600	-	None	SSL/TLS	None	None	-	0	None	7507	SCSV,TLS_FALLBACK_SCSV	TLS_FALLBACK_SCSV	SCSV
0x030000FE	-	-?-	TLSv13	None	None	-	-?-	SHA256	-	WDM-NULL-SHA256	WDM_WITH_NULL_SHA256	wolfSSL DTLS Multicast
0x030000FF	-	None	SSL/TLS	None	None	-	0	None	5746	INFO_SCSV	EMPTY_RENEGOTIATION_INFO_SCSV	DOC
0x03000A0A	-	-	TLSv13	None	None	-	0	None	8701	GREASE-0A	GREASE_0A	-
0x03001A1A	-	-	TLSv13	None	None	-	0	None	8701	GREASE-1A	GREASE_1A	-
0x03002A2A	-	-	TLSv13	None	None	-	0	None	8701	GREASE-2A	GREASE_2A	-
0x03003A3A	-	-	TLSv13	None	None	-	0	None	8701	GREASE-3A	GREASE_3A	-
0x03004A4A	-	-	TLSv13	None	None	-	0	None	8701	GREASE-4A	GREASE_4A	-
0x03005A5A	-	-	TLSv13	None	None	-	0	None	8701	GREASE-5A	GREASE_5A	-
0x03006A6A	-	-	TLSv13	None	None	-	0	None	8701	GREASE-6A	GREASE_6A	-
0x03007A7A	-	-	TLSv13	None	None	-	0	None	8701	GREASE-7A	GREASE_7A	-
0x03008A8A	-	-	TLSv13	None	None	-	0	None	8701	GREASE-8A	GREASE_8A	-
0x03009A9A	-	-	TLSv13	None	None	-	0	None	8701	GREASE-9A	GREASE_9A	-
0x0300AAAA	-	-	TLSv13	None	None	-	0	None	8701	GREASE-AA	GREASE_AA	-
0x0300BABA	-	-	TLSv13	None	None	-	0	None	8701	GREASE-BA	GREASE_BA	-
0x0300CACA	-	-	TLSv13	None	None	-	0	None	8701	GREASE-CA	GREASE_CA	-
0x0300DADA	-	-	TLSv13	None	None	-	0	None	8701	GREASE-DA	GREASE_DA	-
0x0300EAEA	-	-	TLSv13	None	None	-	0	None	8701	GREASE-EA	GREASE_EA	-
0x0300FAFA	-	-	TLSv13	None	None	-	0	None	8701	GREASE-FA	GREASE_0A	-
#0x00800000	-	nix	PCT	-?-	-?-	-?-	-?-	-?-	-	const	-	for testing only
0x00800001	-	-?-	PCT	-?-	-?-	-?-	-?-	-?-	-	PCT_SSL_CERT_TYPE	PCT1_CERT_X509	PCT
0x00800003	-	-?-	PCT	-?-	-?-	-?-	-?-	-?-	-	PCT_SSL_CERT_TYPE	PCT1_CERT_X509_CHAIN	PCT
0x00810001	-	-?-	PCT	-?-	-?-	-?-	-?-	-?-	-	PCT_SSL_HASH_TYPE	PCT1_HASH_MD5	PCT
0x00810003	-	-?-	PCT	-?-	-?-	-?-	-?-	-?-	-	PCT_SSL_HASH_TYPE	PCT1_HASH_SHA	PCT
0x00820003	-	-?-	PCT	-?-	-?-	-?-	-?-	-?-	-	PCT_SSL_EXCH_TYPE	PCT1_EXCH_RSA_PKCS1	PCT
0x00823004	-	-?-	PCT	-?-	-?-	-?-	-?-	-?-	-	PCT_SSL_CIPHER_TYPE_1ST_HALF	PCT1_CIPHER_RC4	PCT
0x00842840	-	-?-	PCT	-?-	-?-	-?-	-?-	-?-	-	PCT_SSL_CIPHER_TYPE_2ND_HALF	PCT1_ENC_BITS_40|PCT1_MAC_BITS_128	PCT
0x00848040	-	-?-	PCT	-?-	-?-	-?-	-?-	-?-	-	PCT_SSL_CIPHER_TYPE_2ND_HALF	PCT1_ENC_BITS_128|PCT1_MAC_BITS_128	PCT
0x008F8001	-	-?-	PCT	-?-	-?-	-?-	-?-	-?-	-	PCT_SSL_COMPAT	PCT_VERSION_1	PCT
0x02000000	-	weak	SSLv2	RSA(512)	None	None	0	MD5	-?-	NULL-MD5	NULL_WITH_MD5	-
0x02010080	MEDIUM	weak	SSLv2	RSA	RSA	RC4	128	MD5	-?-	RC4-MD5	RC4_128_WITH_MD5	-
0x02020080	WEAK	WEAK	SSLv2	RSA(512)	RSA	RC4	40	MD5	-?-	EXP-RC4-MD5	RC4_128_EXPORT40_WITH_MD5	EXPORT
0x02030080	MEDIUM	weak	SSLv2	RSA	RSA	RC2	128	MD5	-?-	RC2-CBC-MD5,RC2-MD5	RC2_128_CBC_WITH_MD5	-
0x02040080	-?-	weak	SSLv2	RSA(512)	RSA	RC2	40	MD5	-?-	EXP-RC2-CBC-MD5,EXP-RC2-MD5	RC2_128_CBC_EXPORT40_WITH_MD5	EXPORT
0x02050080	MEDIUM	weak	SSLv2	RSA	RSA	IDEA	128	MD5	-?-	IDEA-CBC-MD5	IDEA_128_CBC_WITH_MD5,IDEA_CBC_WITH_MD5	-
0x02060040	LOW	weak	SSLv2	RSA	RSA	DES	56	MD5	-?-	DES-CBC-MD5	DES_64_CBC_WITH_MD5,DES_CBC_WITH_MD5	-
0x02060140	-?-	weak	SSLv2	RSA	RSA	DES	56	SHA1	-?-	DES-CBC-SHA	DES_64_CBC_WITH_SHA	-
0x020700C0	MEDIUM	weak	SSLv2	RSA	RSA	3DES	112	MD5	-?-	DES-CBC3-MD5	DES_192_EDE3_CBC_WITH_MD5	-
0x020701C0	MEDIUM	weak	SSLv2	RSA	RSA	3DES	112	SHA1	-?-	DES-CBC3-SHA	DES_192_EDE3_CBC_WITH_SHA	-
0x02080080	LOW	weak	SSLv2	RSA	RSA	RC4	64	MD5	-?-	RC4-64-MD5,EXP-RC4-64-MD5	RC4_64_WITH_MD5	BSAFE
0x02FF0800	-?-	weak	SSLv2	RSA	RSA	DES	64	MD5	-?-	DES-CFB-M1	DES_64_CFB64_WITH_MD5_1	-
0x02FF0810	-?-	weak	SSLv2	RSA(512)	None	None	0	MD5	-	NULL	NULL	SSLeay
0x02FFFFFF	-	-	SSLv2	None	None	-	0	None	-?-	SSL2_UNFFINED_CIPHER_0x02FFFFFF	SSL2_UNFFINED_CIPHER_0x02FFFFFF	internal
0x03000000	-?-	weak	SSLv3	RSA	None	None	0	MD5	5246	NULL-NULL	NULL_WITH_NULL_NULL	SSLeay
0x03000001	-?-	weak	SSLv3	RSA	RSA	None	0	MD5	5246	NULL-MD5	RSA_WITH_NULL_MD5,RSA_NULL_MD5	EXPORT
0x03000002	-?-	weak	SSLv3	RSA	RSA	None	0	SHA1	5246	NULL-SHA	RSA_WITH_NULL_SHA,RSA_NULL_SHA	-
0x03000003	WEAK	WEAK	SSLv3	RSA(512)	RSA	RC4	40	MD5	4346,6347	EXP-RC4-MD5	RSA_WITH_RC4_40_MD5,RSA_RC4_40_MD5,RSA_EXPORT_WITH_RC4_40_MD5,RC4_128_EXPORT40_WITH_MD5	EXPORT
0x03000004	MEDIUM	weak	SSLv3	RSA	RSA	RC4	128	MD5	5246,6347	RC4-MD5	RSA_WITH_RC4_128_MD5,RSA_RC4_128_MD5,RC4_128_WITH_MD5	-
0x03000005	MEDIUM	weak	SSLv3	RSA	RSA	RC4	128	SHA1	5246,6347	RC4-SHA	RSA_WITH_RC4_128_SHA,RSA_RC4_128_SHA,RC4_128_WITH_SHA	-
0x03000006	-?-	weak	SSLv3	RSA(512)	RSA	RC2	40	MD5	4346	EXP-RC2-CBC-MD5	RSA_WITH_RC2_40_MD5,RSA_RC2_40_MD5,RSA_EXPORT_WITH_RC2_CBC_40_MD5,RC2_128_CBC_EXPORT40_WITH_MD5	EXPORT
0x03000007	MEDIUM	weak	SSLv3	RSA	RSA	IDEA	128	SHA1	5469	IDEA-CBC-SHA	RSA_WITH_IDEA_CBC_SHA,RSA_WITH_IDEA_SHA,RSA_IDEA_128_SHA	-
0x03000008	WEAK	WEAK	SSLv3	RSA(512)	RSA	DES	40	SHA1	4346	EXP-DES-CBC-SHA	RSA_DES_40_CBC_SHA,RSA_EXPORT_WITH_DES40_CBC_SHA	EXPORT
0x03000009	LOW	weak	SSLv3	RSA	RSA	DES	56	SHA1	5469	DES-CBC-SHA	RSA_WITH_DES_CBC_SHA,RSA_DES_64_CBC_SHA	-
0x0300000A	MEDIUM	weak	SSLv3	RSA	RSA	3DES	112	SHA1	5246	DES-CBC3-SHA	RSA_WITH_3DES_EDE_CBC_SHA,RSA_DES_192_CBC3_SHA,DES_192_EDE3_CBC_WITH_SHA	-
0x0300000B	-?-	weak	SSLv3	DH/DSS	DH	DES	40	SHA1	4346	EXP-DH-DSS-DES-CBC-SHA	DH_DSS_DES_40_CBC_SHA,DH_DSS_EXPORT_WITH_DES40_CBC_SHA	EXPORT
0x0300000C	LOW	weak	SSLv3	DH/DSS	DH	DES	56	SHA1	5469	DH-DSS-DES-CBC-SHA	DH_DSS_DES_64_CBC_SHA,DH_DSS_WITH_DES_CBC_SHA	-
0x0300000D	MEDIUM	weak	SSLv3	DH/DSS	DH	3DES	112	SHA1	5246	DH-DSS-DES-CBC3-SHA	DH_DSS_DES_192_CBC3_SHA,DH_DSS_WITH_3DES_EDE_CBC_SHA	-
0x0300000E	-?-	weak	SSLv3	DH/RSA	DH	DES	40	SHA1	4346	EXP-DH-RSA-DES-CBC-SHA	DH_RSA_DES_40_CBC_SHA,DH_RSA_EXPORT_WITH_DES40_CBC_SHA	EXPORT
0x0300000F	LOW	weak	SSLv3	DH/RSA	DH	DES	56	SHA1	5469	DH-RSA-DES-CBC-SHA	DH_RSA_DES_64_CBC_SHA,DH_RSA_WITH_DES_CBC_SHA	-
0x03000010	MEDIUM	weak	SSLv3	DH/RSA	DH	3DES	112	SHA1	5246	DH-RSA-DES-CBC3-SHA	DH_RSA_DES_192_CBC3_SHA,DH_RSA_WITH_3DES_EDE_CBC_SHA	-
0x03000011	-?-	weak	SSLv3	DH(512)	DSS	DES	40	SHA1	4346	EXP-EDH-DSS-DES-CBC-SHA	EDH_DSS_DES_40_CBC_SHA,DHE_DSS_DES_40_CBC_SHA,EDH_DSS_EXPORT_WITH_DES40_CBC_SHA	EXPORT
0x03000012	LOW	weak	SSLv3	DH	DSS	DES	56	SHA1	5469	EDH-DSS-DES-CBC-SHA,EDH-DSS-CBC-SHA	EDH_DSS_DES_64_CBC_SHA,DHE_DSS_DES_64_CBC_SHA,DHE_DSS_WITH_DES_CBC_SHA,EDH_DSS_WITH_DES_CBC_SHA	-
0x03000013	MEDIUM	weak	SSLv3	DH	DSS	3DES	112	SHA1	5246	EDH-DSS-DES-CBC3-SHA,DHE-DSS-DES-CBC3-SHA	EDH_DSS_DES_192_CBC3_SHA,DHE_DSS_DES_192_CBC3_SHA,DHE_DSS_WITH_3DES_EDE_CBC_SHA,EDH_DSS_WITH_3DES_EDE_CBC_SHA	-
0x03000014	LOW	weak	SSLv3	DH(512)	RSA	DES	40	SHA1	4346	EXP-EDH-RSA-DES-CBC-SHA	EDH_RSA_DES_40_CBC_SHA,DHE_RSA_DES_40_CBC_SHA,DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,EDH_RSA_EXPORT_WITH_DES40_CBC_SHA	EXPORT
0x03000015	LOW	weak	SSLv3	DH	RSA	DES	56	SHA1	5469	EDH-RSA-DES-CBC-SHA	EDH_RSA_DES_64_CBC_SHA,DHE_RSA_DES_64_CBC_SHA,DHE_RSA_WITH_DES_CBC_SHA,EDH_RSA_WITH_DES_CBC_SHA	-
0x03000016	MEDIUM	weak	SSLv3	DH	RSA	3DES	112	SHA1	5246	EDH-RSA-DES-CBC3-SHA,DHE-RSA-DES-CBC3-SHA	EDH_RSA_DES_192_CBC3_SHA,DHE_RSA_DES_192_CBC3_SHA,DHE_RSA_WITH_3DES_EDE_CBC_SHA,EDH_RSA_WITH_3DES_EDE_CBC_SHA	-
0x03000017	WEAK	WEAK	SSLv3	DH(512)	None	RC4	40	MD5	4346,6347	EXP-ADH-RC4-MD5	ADH_RC4_40_MD5,DH_anon_EXPORT_WITH_RC4_40_MD5	EXPORT
0x03000018	MEDIUM	weak	SSLv3	DH	None	RC4	128	MD5	5246,6347	ADH-RC4-MD5,DHanon-RC4-MD5	ADH_RC4_128_MD5,DH_anon_WITH_RC4_MD5,DH_anon_WITH_RC4_128_MD5	-
0x03000019	-?-	weak	SSLv3	DH(512)	None	DES	40	SHA1	4346	EXP-ADH-DES-CBC-SHA	ADH_DES_40_CBC_SHA,DH_anon_EXPORT_WITH_DES40_CBC_SHA	EXPORT
0x0300001A	LOW	weak	SSLv3	DH	None	DES	56	SHA1	5469	ADH-DES-CBC-SHA,DHanon-DES-CBC-SHA	ADH_DES_64_CBC_SHA,DH_anon_WITH_DES_CBC_SHA	-
0x0300001B	MEDIUM	weak	SSLv3	DH	None	3DES	112	SHA1	5246	ADH-DES-CBC3-SHA,DHanon-DES-CBC3-SHA	ADH_DES_192_CBC_SHA,DH_anon_WITH_3DES_EDE_CBC_SHA	-
0x0300001C	-?-	weak	SSLv3	FZA	FZA	None	0	SHA1	5246	FZA-NULL-SHA	FZA_DMS_NULL_SHA,FORTEZZA_KEA_WITH_NULL_SHA	M
0x0300001D	MEDIUM	weak	SSLv3	FZA	FZA	FZA	0	SHA1	5246	FZA-FZA-SHA,FZA-FZA-CBC-SHA	FZA_DMS_FZA_SHA,FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA	M
0x0300001E	WEAK	WEAK	SSLv3	FZA	FZA	RC4	128	SHA1	-	FZA-RC4-SHA	FZA_DMS_RC4_SHA	M
#0x0300001E-bug	LOW	weak	SSLv3	KRB5	KRB5	DES	56	SHA1	2712	KRB5-DES-CBC-SHA	KRB5_DES_64_CBC_SHA,KRB5_WITH_DES_CBC_SHA	P
0x0300001F	MEDIUM	weak	SSLv3	KRB5	KRB5	3DES	112	SHA1	2712	KRB5-DES-CBC3-SHA	KRB5_DES_192_CBC3_SHA,KRB5_WITH_3DES_EDE_CBC_SHA	P
0x03000020	MEDIUM	weak	SSLv3	KRB5	KRB5	RC4	128	SHA1	2712,6347	KRB5-RC4-SHA	KRB5_RC4_128_SHA,KRB5_WITH_RC4_128_SHA	P
0x03000021	MEDIUM	weak	SSLv3	KRB5	KRB5	IDEA	128	SHA1	2712	KRB5-IDEA-CBC-SHA	KRB5_IDEA_128_CBC_SHA,KRB5_WITH_IDEA_CBC_SHA	P
0x03000022	LOW	weak	SSLv3	KRB5	KRB5	DES	56	MD5	2712	KRB5-DES-CBC-MD5	KRB5_DES_64_CBC_MD5,KRB5_WITH_DES_CBC_MD5	P
0x03000023	MEDIUM	weak	SSLv3	KRB5	KRB5	3DES	112	MD5	2712	KRB5-DES-CBC3-MD5	KRB5_DES_192_CBC3_MD5,KRB5_WITH_3DES_EDE_CBC_MD5	P
0x03000024	MEDIUM	weak	SSLv3	KRB5	KRB5	RC4	128	MD5	2712,6347	KRB5-RC4-MD5	KRB5_RC4_128_MD5,KRB5_WITH_RC4_128_MD5	P
0x03000025	MEDIUM	weak	SSLv3	KRB5	KRB5	IDEA	128	MD5	2712	KRB5-IDEA-CBC-MD5	KRB5_IDEA_128_CBC_MD5,KRB5_WITH_IDEA_CBC_MD5	P
0x03000026	-?-	weak	SSLv3	KRB5	KRB5	DES	40	SHA1	2712	EXP-KRB5-DES-CBC-SHA	KRB5_DES_40_CBC_SHA,KRB5_EXPORT_WITH_DES_CBC_40_SHA	EXPORT,P
0x03000027	-?-	weak	SSLv3	KRB5	KRB5	RC2	40	SHA1	2712	EXP-KRB5-RC2-CBC-SHA	KRB5_RC2_40_CBC_SHA,KRB5_EXPORT_WITH_RC2_CBC_40_SHA	EXPORT,P
0x03000028	-?-	weak	SSLv3	KRB5	KRB5	RC4	40	SHA1	2712,6347	EXP-KRB5-RC4-SHA	KRB5_RC4_40_SHA,KRB5_EXPORT_WITH_RC4_40_SHA	EXPORT,P
0x03000029	-?-	weak	SSLv3	KRB5	KRB5	DES	40	MD5	2712	EXP-KRB5-DES-CBC-MD5	KRB5_DES_40_CBC_MD5,KRB5_EXPORT_WITH_DES_CBC_40_MD5	EXPORT,P
0x0300002A	-?-	weak	SSLv3	KRB5	KRB5	RC2	40	MD5	2712	EXP-KRB5-RC2-CBC-MD5	KRB5_RC2_40_CBC_MD5,KRB5_EXPORT_WITH_RC2_CBC_40_MD5,KRB5_WITH_RC2_CBC_40_MD5	EXPORT,P
0x0300002B	-?-	weak	SSLv3	KRB5	KRB5	RC4	40	MD5	2712,6347	EXP-KRB5-RC4-MD5	KRB5_RC4_40_MD5,KRB5_EXPORT_WITH_RC4_40_MD5	EXPORT,P
0x0300002C	-?-	weak	SSLv3	DH	RSA	None	0	SHA1	4785	PSK-SHA,PSK-NULL-SHA	PSK_WITH_NULL_SHA	-
0x0300002D	-?-	weak	SSLv3	DHEPSK	PSK	None	0	SHA1	4785	DHE-PSK-SHA,DHE-PSK-NULL-SHA	DHE_PSK_WITH_NULL_SHA	FIXME
0x0300002E	-?-	weak	SSLv3	RSAPSK	PSK	None	0	SHA1	4785	RSA-PSK-SHA,RSA-PSK-NULL-SHA	RSA_PSK_WITH_NULL_SHA	FIXME
0x0300002F	HIGH	weak	SSLv3	RSA	RSA	AES	128	SHA1	5246	AES128-SHA	RSA_WITH_AES_128_CBC_SHA,RSA_WITH_AES_128_SHA	-
0x03000030	HIGH	weak	SSLv3	DH	DSS	AES	128	SHA1	5246	DH-DSS-AES128-SHA	DH_DSS_WITH_AES_128_SHA,DH_DSS_WITH_AES_128_CBC_SHA	-
0x03000031	HIGH	weak	SSLv3	DH	RSA	AES	128	SHA1	5246	DH-RSA-AES128-SHA	DH_RSA_WITH_AES_128_SHA,DH_RSA_WITH_AES_128_CBC_SHA	-
0x03000032	HIGH	weak	SSLv3	DH	DSS	AES	128	SHA1	5246	DHE-DSS-AES128-SHA,EDH-DSS-AES128-SHA	DHE_DSS_WITH_AES_128_CBC_SHA,DHE_DSS_WITH_AES_128_SHA	BSAFE
0x03000033	HIGH	weak	SSLv3	DH	RSA	AES	128	SHA1	5246	DHE-RSA-AES128-SHA,EDH-RSA-AES128-SHA	DHE_RSA_WITH_AES_128_CBC_SHA,DHE_RSA_WITH_AES_128_SHA	-
0x03000034	HIGH	weak	SSLv3	DH	None	AES	128	SHA1	5246	ADH-AES128-SHA	ADH_WITH_AES_128_SHA,DH_anon_WITH_AES_128_CBC_SHA	-
0x03000035	HIGH	weak	SSLv3	RSA	RSA	AES	256	SHA1	5246	AES256-SHA	RSA_WITH_AES_256_SHA,RSA_WITH_AES_256_CBC_SHA	-
0x03000036	HIGH	weak	SSLv3	DH	DSS	AES	256	SHA1	5246	DH-DSS-AES256-SHA	DH_DSS_WITH_AES_256_SHA,DH_DSS_WITH_AES_256_CBC_SHA	-
0x03000037	HIGH	weak	SSLv3	DH	RSA	AES	256	SHA1	5246	DH-RSA-AES256-SHA	DH_RSA_WITH_AES_256_SHA,DH_RSA_WITH_AES_256_CBC_SHA	-
0x03000038	HIGH	weak	SSLv3	DH	DSS	AES	256	SHA1	5246	DHE-DSS-AES256-SHA,EDH-DSS-AES256-SHA	DHE_DSS_WITH_AES_256_SHA,DHE_DSS_WITH_AES_256_CBC_SHA	-
0x03000039	HIGH	weak	SSLv3	DH	RSA	AES	256	SHA1	5246	DHE-RSA-AES256-SHA,EDH-RSA-AES256-SHA	DHE_RSA_WITH_AES_256_SHA,DHE_RSA_WITH_AES_256_CBC_SHA	-
0x0300003A	HIGH	weak	SSLv3	DH	None	AES	256	SHA1	5246	ADH-AES256-SHA	ADH_WITH_AES_256_SHA,DH_anon_WITH_AES_256_CBC_SHA	-
0x0300003B	-?-	weak	TLSv12	RSA	RSA	None	0	SHA256	5246	NULL-SHA256	RSA_WITH_NULL_SHA256	L
0x0300003C	HIGH	weak	TLSv12	RSA	RSA	AES	128	SHA256	5246	AES128-SHA256	RSA_WITH_AES_128_SHA256,RSA_WITH_AES_128_CBC_SHA256	L
0x0300003D	HIGH	weak	TLSv12	RSA	RSA	AES	256	SHA256	5246	AES256-SHA256	RSA_WITH_AES_256_SHA256,RSA_WITH_AES_256_CBC_SHA256	L
0x0300003E	HIGH	weak	TLSv12	DH/DSS	DH	AES	128	SHA256	5246	DH-DSS-AES128-SHA256	DH_DSS_WITH_AES_128_SHA256,DH_DSS_WITH_AES_128_CBC_SHA256	L
0x0300003F	HIGH	weak	TLSv12	DH/RSA	DH	AES	128	SHA256	5246	DH-RSA-AES128-SHA256	DH_RSA_WITH_AES_128_SHA256,DH_RSA_WITH_AES_128_CBC_SHA256	L
0x03000040	HIGH	weak	TLSv12	DH	DSS	AES	128	SHA256	5246	DHE-DSS-AES128-SHA256	DHE_DSS_WITH_AES_128_SHA256,DHE_DSS_WITH_AES_128_CBC_SHA256	L
0x03000041	HIGH	weak	TLSv1	RSA	RSA	CAMELLIA	128	SHA1	4132,5932	CAMELLIA128-SHA	RSA_WITH_CAMELLIA_128_CBC_SHA	-
0x03000042	HIGH	weak	TLSv1	DH	DSS	CAMELLIA	128	SHA1	4132,5932	DH-DSS-CAMELLIA128-SHA	DH_DSS_WITH_CAMELLIA_128_CBC_SHA	-
0x03000043	HIGH	weak	TLSv1	DH	RSA	CAMELLIA	128	SHA1	4132,5932	DH-RSA-CAMELLIA128-SHA	DH_RSA_WITH_CAMELLIA_128_CBC_SHA	-
0x03000044	HIGH	weak	TLSv1	DH	DSS	CAMELLIA	128	SHA1	4132,5932	DHE-DSS-CAMELLIA128-SHA	DHE_DSS_WITH_CAMELLIA_128_CBC_SHA	-
0x03000045	HIGH	weak	TLSv1	DH	RSA	CAMELLIA	128	SHA1	4132,5932	DHE-RSA-CAMELLIA128-SHA	DHE_RSA_WITH_CAMELLIA_128_CBC_SHA	-
0x03000046	HIGH	weak	TLSv1	DH	None	CAMELLIA	128	SHA1	4132,5932	ADH-CAMELLIA128-SHA	ADH_WITH_CAMELLIA_128_CBC_SHA,DH_anon_WITH_CAMELLIA_128_CBC_SHA	-
0x03000060	WEAK	WEAK	SSLv3	RSA(1024)	RSA	RC4	56	MD5	-?-	EXP1024-RC4-MD5	RSA_EXPORT1024_WITH_RC4_56_MD5	EXPORT
0x03000061	-?-	weak	SSLv3	RSA(1024)	RSA	RC2	56	MD5	-?-	EXP1024-RC2-CBC-MD5	RSA_EXPORT1024_WITH_RC2_CBC_56_MD5	EXPORT
0x03000062	-?-	weak	SSLv3	RSA(1024)	RSA	DES	56	SHA1	-?-	EXP1024-DES-CBC-SHA,EXP-DES-56-SHA	RSA_EXPORT1024_WITH_DES_CBC_SHA	EXPORT
0x03000063	-?-	weak	SSLv3	DH(1024)	DSS	DES	56	SHA1	-?-	EXP1024-DHE-DSS-DES-CBC-SHA,EXP-EDH-DSS-DES-56-SHA	DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA,DHE_DSS_EXPORT_WITH_DES40_CBC_SHA	EXPORT,T
0x03000064	WEAK	WEAK	SSLv3	RSA(1024)	RSA	RC4	56	SHA1	-?-	EXP1024-RC4-SHA,EXP-RC4-56-SHA	RSA_EXPORT1024_WITH_RC4_56_SHA	EXPORT
0x03000065	WEAK	WEAK	SSLv3	DH(1024)	DSS	RC4	56	SHA1	-?-	EXP1024-DHE-DSS-RC4-SHA,EXP-EDH-DSS-RC4-56-SHA	DHE_DSS_EXPORT1024_WITH_RC4_56_SHA	EXPORT,BSAFE
0x03000066	MEDIUM	weak	SSLv3	DH	DSS	RC4	128	SHA1	-?-	DHE-DSS-RC4-SHA,EDH-DSS-RC4-SHA	DHE_DSS_WITH_RC4_128_SHA	BSAFE
0x03000067	HIGH	weak	TLSv12	DH	RSA	AES	128	SHA256	5246	DHE-RSA-AES128-SHA256	DHE_RSA_WITH_AES_128_SHA256,DHE_RSA_WITH_AES_128_CBC_SHA256	L
0x03000068	HIGH	weak	TLSv12	DH/DSS	DH	AES	256	SHA256	5246	DH-DSS-AES256-SHA256	DH_DSS_WITH_AES_256_SHA256,DH_DSS_WITH_AES_256_CBC_SHA256	-
0x03000069	HIGH	weak	TLSv12	DH/RSA	DH	AES	256	SHA256	5246	DH-RSA-AES256-SHA256	DH_RSA_WITH_AES_256_SHA256,DH_RSA_WITH_AES_256_CBC_SHA256	-
0x0300006A	HIGH	weak	TLSv12	DH	DSS	AES	256	SHA256	5246	DHE-DSS-AES256-SHA256	DHE_DSS_WITH_AES_256_SHA256,DHE_DSS_WITH_AES_256_CBC_SHA256	L
0x0300006B	HIGH	weak	TLSv12	DH	RSA	AES	256	SHA256	5246	DHE-RSA-AES256-SHA256	DHE_RSA_WITH_AES_256_SHA256,DHE_RSA_WITH_AES_256_CBC_SHA256	L
0x0300006C	HIGH	weak	TLSv12	DH	None	AES	128	SHA256	5246	ADH-AES128-SHA256	ADH_WITH_AES_128_SHA256,DH_anon_WITH_AES_128_CBC_SHA256	L
0x0300006D	HIGH	weak	TLSv12	DH	None	AES	256	SHA256	5246	ADH-AES256-SHA256	ADH_WITH_AES_256_SHA256,DH_anon_WITH_AES_256_CBC_SHA256	L
0x03000070	-?-	weak	SSLv3	DH	DSS	CAST	128	SHA1	-	DHE-DSS-CAST128-CBC-SHA	DHE_DSS_WITH_CAST_128_CBC_SHA	PGP,H
0x03000071	-?-	weak	SSLv3	DH	DSS	CAST	128	RIPEMD	-	DHE-DSS-CAST128-CBC-RMD	DHE_DSS_WITH_CAST_128_CBC_RMD	PGP,H
0x03000072	-?-	weak	SSLv3	DH	DSS	3DES	128	RIPEMD	-?-	DHE-DSS-3DES-EDE-CBC-RMD	DHE_DSS_WITH_3DES_EDE_CBC_RMD	PGP
0x03000073	-?-	weak	SSLv3	DH	DSS	AES	128	RIPEMD	-?-	DHE-DSS-AES128-CBC-RMD	DHE_DSS_WITH_AES_128_CBC_RMD	PGP
0x03000074	-?-	weak	SSLv3	DH	DSS	AES	128	RIPEMD	-?-	DHE-DSS-AES256-CBC-RMD	DHE_DSS_WITH_AES_256_CBC_RMD	PGP
0x03000075	-?-	weak	SSLv3	DH	RSA	CAST	128	SHA1	-	DHE-RSA-CAST128-CBC-SHA	DHE_RSA_WITH_CAST_128_CBC_SHA	PGP,H
0x03000076	-?-	weak	SSLv3	DH	RSA	CAST	128	RIPEMD	-	DHE-RSA-CAST128-CBC-RMD	DHE_RSA_WITH_CAST_128_CBC_RMD	PGP,H
0x03000077	-?-	weak	SSLv3	DH	RSA	3DES	128	RIPEMD	-?-	DHE-RSA-3DES-EDE-CBC-RMD	DHE_RSA_WITH_3DES_EDE_CBC_RMD	PGP
0x03000078	-?-	weak	SSLv3	DH	RSA	AES	128	RIPEMD	-?-	DHE-RSA-AES128-CBC-RMD	DHE_RSA_WITH_AES_128_CBC_RMD	PGP
0x03000079	-?-	weak	SSLv3	DH	RSA	AES	128	RIPEMD	-?-	DHE-RSA-AES256-CBC-RMD	DHE_RSA_WITH_AES_256_CBC_RMD	PGP
0x0300007A	-?-	weak	SSLv3	RSA	RSA	CAST	128	SHA1	-	RSA-CAST128-CBC-SHA	RSA_WITH_CAST_128_CBC_SHA	H
0x0300007B	-?-	weak	SSLv3	RSA	RSA	CAST	128	RIPEMD	-	RSA-CAST128-CBC-RMD	RSA_WITH_CAST_128_CBC_RMD	H
0x0300007C	-?-	weak	SSLv3	RSA	RSA	3DES	128	RIPEMD	-?-	RSA-3DES-EDE-CBC-RMD	RSA_WITH_3DES_EDE_CBC_RMD	-
0x0300007D	-?-	weak	SSLv3	RSA	RSA	AES	128	RIPEMD	-?-	RSA-AES128-CBC-RMD	RSA_WITH_AES_128_CBC_RMD	-
0x0300007E	-?-	weak	SSLv3	RSA	RSA	AES	128	RIPEMD	-?-	RSA-AES256-CBC-RMD	RSA_WITH_AES_256_CBC_RMD	-
0x03000080	HIGH	HIGH	SSLv3	GOST	GOST94	GOST89	256	GOST89	5830	GOST94-GOST89-GOST89	GOSTR341094_WITH_28147_CNT_IMIT	G
0x03000081	HIGH	HIGH	SSLv3	GOST	GOST01	GOST89	256	GOST89	5830	GOST2001-GOST89-GOST89	GOSTR341001_WITH_28147_CNT_IMIT	G
0x03000082	-?-	weak	SSLv3	GOST	GOST94	None	0	GOST94	-?-	GOST94-NULL-GOST94	GOSTR341094_WITH_NULL_GOSTR3411	G
0x03000083	-?-	weak	SSLv3	GOST	GOST01	None	0	GOST94	-?-	GOST2001-NULL-GOST94	GOSTR341001_WITH_NULL_GOSTR3411	G
0x03000084	HIGH	weak	TLSv1	RSA	RSA	CAMELLIA	256	SHA1	4132,5932	CAMELLIA256-SHA	RSA_WITH_CAMELLIA_256_CBC_SHA	-
0x03000085	HIGH	weak	TLSv1	DSS	DH	CAMELLIA	256	SHA1	4132,5932	DH-DSS-CAMELLIA256-SHA	DH_DSS_WITH_CAMELLIA_256_CBC_SHA	-
0x03000086	HIGH	weak	TLSv1	RSA	DH	CAMELLIA	256	SHA1	4132,5932	DH-RSA-CAMELLIA256-SHA	DH_RSA_WITH_CAMELLIA_256_CBC_SHA	-
0x03000087	HIGH	weak	TLSv1	DH	DSS	CAMELLIA	256	SHA1	4132,5932	DHE-DSS-CAMELLIA256-SHA	DHE_DSS_WITH_CAMELLIA_256_CBC_SHA	-
0x03000088	HIGH	weak	TLSv1	DH	RSA	CAMELLIA	256	SHA1	4132,5932	DHE-RSA-CAMELLIA256-SHA	DHE_RSA_WITH_CAMELLIA_256_CBC_SHA	-
0x03000089	HIGH	weak	TLSv1	DH	None	CAMELLIA	256	SHA1	4132,5932	ADH-CAMELLIA256-SHA	ADH_WITH_CAMELLIA_256_CBC_SHA,DH_anon_WITH_CAMELLIA_256_CBC_SHA	-
0x0300008A	MEDIUM	medium	SSLv3	PSK	PSK	RC4	128	SHA1	4279,6347	PSK-RC4-SHA	PSK_WITH_RC4_128_SHA,PSK_WITH_RC4_128_CBC_SHA	-
0x0300008B	MEDIUM	medium	SSLv3	PSK	PSK	3DES	112	SHA1	4279	PSK-3DES-EDE-CBC-SHA,PSK-3DES-SHA	PSK_WITH_3DES_EDE_CBC_SHA	-
0x0300008C	HIGH	medium	SSLv3	PSK	PSK	AES	128	SHA1	4279	PSK-AES128-CBC-SHA	PSK_WITH_AES_128_CBC_SHA	-
0x0300008D	HIGH	medium	SSLv3	PSK	PSK	AES	256	SHA1	4279	PSK-AES256-CBC-SHA	PSK_WITH_AES_256_CBC_SHA	-
0x0300008E	-?-	medium	TLSv12	DHE	PSK	RC4	128	SHA1	4279,6347	DHE-PSK-RC4-SHA	DHE_PSK_WITH_RC4_128_SHA,DHE_PSK_WITH_RC4_128_CBC_SHA	FIXME
0x0300008F	-?-	medium	TLSv12	DHE	PSK	3DES	112	SHA1	4279	DHE-PSK-3DES-SHA	DHE_PSK_WITH_3DES_EDE_CBC_SHA	FIXME
0x03000090	HIGH	medium	TLSv12	DHE	PSK	AES	128	SHA1	4279	DHE-PSK-AES128-SHA,DHE-PSK-AES128-CBC-SHA	DHE_PSK_WITH_AES_128_CBC_SHA	-
0x03000091	HIGH	medium	TLSv12	DHE	PSK	AES	256	SHA1	4279	DHE-PSK-AES256-SHA,DHE-PSK-AES256-CBC-SHA	DHE_PSK_WITH_AES_256_CBC_SHA	-
0x03000092	MEDIUM	medium	SSLv3	RSAPSK	RSA	RC4	128	SHA1	4279,6347	RSA-PSK-RC4-SHA	RSA_PSK_WITH_RC4_128_SHA,RSA_PSK_WITH_RC4_128_CBC_SHA	-
0x03000093	-?-	medium	SSLv3	RSAPSK	RSA	3DES	112	SHA1	4279	RSA-PSK-3DES-SHA,RSA-PSK-3DES-EDE-CBC-SHA	RSA_PSK_WITH_3DES_EDE_CBC_SHA	-
0x03000094	HIGH	medium	SSLv3	RSAPSK	AES	AES	128	SHA1	4279	RSA-PSK-AES128-SHA,RSA-PSK-AES128-CBC-SHA	RSA_PSK_WITH_AES_128_CBC_SHA	-
0x03000095	HIGH	medium	SSLv3	RSAPSK	AES	RSA	256	SHA1	4279	RSA-PSK-AES256-SHA,RSA-PSK-AES256-CBC-SHA	RSA_PSK_WITH_AES_256_CBC_SHA	-
0x03000096	MEDIUM	weak	TLSv1	RSA	RSA	SEED	128	SHA1	4162	SEED-SHA	RSA_WITH_SEED_SHA,RSA_WITH_SEED_CBC_SHA	OSX
0x03000097	MEDIUM	weak	TLSv1	DH/DSS	DH	SEED	128	SHA1	4162	DH-DSS-SEED-SHA	DH_DSS_WITH_SEED_SHA,DH_DSS_WITH_SEED_CBC_SHA	-
0x03000098	MEDIUM	weak	TLSv1	DH/RSA	DH	SEED	128	SHA1	4162	DH-RSA-SEED-SHA	DH_RSA_WITH_SEED_SHA,DH_RSA_WITH_SEED_CBC_SHA	-
0x03000099	MEDIUM	weak	TLSv1	DH	DSS	SEED	128	SHA1	4162	DHE-DSS-SEED-SHA	DHE_DSS_WITH_SEED_SHA,DHE_DSS_WITH_SEED_CBC_SHA	OSX
0x0300009A	MEDIUM	weak	TLSv1	DH	RSA	SEED	128	SHA1	4162	DHE-RSA-SEED-SHA	DHE_RSA_WITH_SEED_SHA,DHE_RSA_WITH_SEED_CBC_SHA	OSX
0x0300009B	MEDIUM	weak	TLSv1	DH	None	SEED	128	SHA1	4162	ADH-SEED-SHA,DHanon-SEED-SHA	ADH_WITH_SEED_SHA,ADH_WITH_SEED_SHA_SHA,DH_anon_WITH_SEED_CBC_SHA	OSX
0x0300009C	HIGH	HIGH	TLSv12	RSA	RSA	AESGCM	128	AEAD	5288	AES128-GCM-SHA256	RSA_WITH_AES_128_GCM_SHA256	L
0x0300009D	HIGH	HIGH	TLSv12	RSA	RSA	AESGCM	256	AEAD	5288	AES256-GCM-SHA384	RSA_WITH_AES_256_GCM_SHA384	L
0x0300009E	HIGH	HIGH	TLSv12	DH	RSA	AESGCM	128	AEAD	5288	DHE-RSA-AES128-GCM-SHA256	DHE_RSA_WITH_AES_128_GCM_SHA256	L
0x0300009F	HIGH	HIGH	TLSv12	DH	RSA	AESGCM	256	AEAD	5288	DHE-RSA-AES256-GCM-SHA384	DHE_RSA_WITH_AES_256_GCM_SHA384	L
0x030000A0	HIGH	HIGH	TLSv12	DH/RSA	DH	AESGCM	128	AEAD	5288	DH-RSA-AES128-GCM-SHA256	DH_RSA_WITH_AES_128_GCM_SHA256	-
0x030000A1	HIGH	HIGH	TLSv12	DH/RSA	DH	AESGCM	256	AEAD	5288	DH-RSA-AES256-GCM-SHA384	DH_RSA_WITH_AES_256_GCM_SHA384	-
0x030000A2	HIGH	HIGH	TLSv12	DH	DSS	AESGCM	128	AEAD	5288	DHE-DSS-AES128-GCM-SHA256	DHE_DSS_WITH_AES_128_GCM_SHA256	L
0x030000A3	HIGH	HIGH	TLSv12	DH	DSS	AESGCM	256	AEAD	5288	DHE-DSS-AES256-GCM-SHA384	DHE_DSS_WITH_AES_256_GCM_SHA384	L
0x030000A4	HIGH	HIGH	TLSv12	DH/DSS	DH	AESGCM	128	AEAD	5288	DH-DSS-AES128-GCM-SHA256	DH_DSS_WITH_AES_128_GCM_SHA256	-
0x030000A5	HIGH	HIGH	TLSv12	DH/DSS	DH	AESGCM	256	AEAD	5288	DH-DSS-AES256-GCM-SHA384	DH_DSS_WITH_AES_256_GCM_SHA384	-
0x030000A6	HIGH	weak	TLSv12	DH	None	AESGCM	128	AEAD	5288	ADH-AES128-GCM-SHA256	ADH_WITH_AES_128_GCM_SHA256,DH_anon_WITH_AES_128_GCM_SHA256	L
0x030000A7	HIGH	weak	TLSv12	DH	None	AESGCM	256	AEAD	5288	ADH-AES256-GCM-SHA384	ADH_WITH_AES_256_GCM_SHA384,DH_anon_WITH_AES_256_GCM_SHA384,DH_anon_WITH_AES_256_GCM_SHA256	L,S
0x030000A8	HIGH	high	TLSv12	PSK	PSK	AESGCM	128	SHA256	5487	PSK-AES128-GCM-SHA256	PSK_WITH_AES_128_GCM_SHA256	-
0x030000A9	HIGH	high	TLSv12	PSK	PSK	AESGCM	256	SHA384	5487	PSK-AES256-GCM-SHA384	PSK_WITH_AES_256_GCM_SHA384	-
0x030000AA	HIGH	high	TLSv12	DHE	PSK	AESGCM	128	SHA256	5487	DHE-PSK-AES128-GCM-SHA256	DHE_PSK_WITH_AES_128_GCM_SHA256	-
0x030000AB	HIGH	high	TLSv12	DHE	PSK	AESGCM	256	SHA384	5487	DHE-PSK-AES256-GCM-SHA384	DHE_PSK_WITH_AES_256_GCM_SHA384	-
0x030000AC	HIGH	high	TLSv12	RSA	PSK	AESGCM	128	SHA256	5487	RSA-PSK-AES128-GCM-SHA256	RSA_PSK_WITH_AES_128_GCM_SHA256	-
0x030000AD	HIGH	high	TLSv12	RSA	PSK	AESGCM	256	SHA384	5487	RSA-PSK-AES256-GCM-SHA384,PSK-RSA-AES256-GCM-SHA384	RSA_PSK_WITH_AES_256_GCM_SHA384	-
0x030000AE	HIGH	medium	TLSv1	PSK	PSK	AES	128	SHA256	5487	PSK-AES128-SHA256,PSK-AES128-CBC-SHA256	PSK_WITH_AES_128_CBC_SHA256	K
0x030000AF	HIGH	medium	TLSv1	PSK	PSK	AES	256	SHA384	5487	PSK-AES256-SHA384,PSK-AES256-CBC-SHA384	PSK_WITH_AES_256_CBC_SHA384	K
0x030000B0	-?-	weak	TLSv1	PSK	PSK	None	0	SHA256	5487	PSK-SHA256,PSK-NULL-SHA256	PSK_WITH_NULL_SHA256	-
0x030000B1	-?-	weak	TLSv1	PSK	PSK	None	0	SHA384	5487	PSK-SHA384,PSK-NULL-SHA384	PSK_WITH_NULL_SHA384	-
0x030000B2	HIGH	medium	TLSv1	DHEPSK	PSK	AES	128	SHA256	5487	DHE-PSK-AES128-SHA256,DHE-PSK-AES128-CBC-SHA256	DHE_PSK_WITH_AES_128_CBC_SHA256	-
0x030000B3	HIGH	medium	TLSv1	DHE	PSK	AES	256	SHA384	5487	DHE-PSK-AES256-SHA384,DHE-PSK-AES256-CBC-SHA384	DHE_PSK_WITH_AES_256_CBC_SHA384	-
0x030000B4	-?-	weak	TLSv12	DHE	PSK	None	0	SHA256	5487	DHE-PSK-SHA256,DHE-PSK-NULL-SHA256	DHE_PSK_WITH_NULL_SHA256	-
0x030000B5	-?-	weak	TLSv12	DHE	PSK	None	0	SHA384	5487	DHE-PSK-SHA384,DHE-PSK-NULL-SHA384	DHE_PSK_WITH_NULL_SHA384	-
0x030000B6	HIGH	medium	TLSv1	RSAPSK	PSK	AES	128	SHA256	5487	RSA-PSK-AES128-SHA256,RSA-PSK-AES128-CBC-SHA256	RSA_PSK_WITH_AES_128_CBC_SHA256	-
0x030000B7	HIGH	medium	TLSv1	RSAPSK	PSK	AES	256	SHA384	5487	RSA-PSK-AES256-SHA384,RSA-PSK-AES256-CBC-SHA384	RSA_PSK_WITH_AES_256_CBC_SHA384	-
0x030000B8	-?-	weak	TLSv1	RSAPSK	RSA	None	0	SHA256	5487	RSA-PSK-SHA256,RSA-PSK-NULL-SHA256	RSA_PSK_WITH_NULL_SHA256	-
0x030000B9	-?-	weak	TLSv1	RSAPSK	RSA	None	0	SHA364	5487	RSA-PSK-SHA384,RSA-PSK-NULL-SHA384	RSA_PSK_WITH_NULL_SHA384	-
0x030000BA	HIGH	weak	TLSv12	RSA	RSA	CAMELLIA	128	SHA256	5932	CAMELLIA128-SHA256,RSA-CAMELLIA128-SHA256	RSA_WITH_CAMELLIA_128_CBC_SHA256	Q
0x030000BB	HIGH	weak	TLSv12	DH	DSS	CAMELLIA	128	SHA256	5932	DH-DSS-CAMELLIA128-SHA256	DH_DSS_WITH_CAMELLIA_128_CBC_SHA256	Q
0x030000BC	HIGH	weak	TLSv12	DH	RSA	CAMELLIA	128	SHA256	5932	DH-RSA-CAMELLIA128-SHA256	DH_RSA_WITH_CAMELLIA_128_CBC_SHA256	Q
0x030000BD	HIGH	weak	TLSv12	DH	DSS	CAMELLIA	128	SHA256	5932	DHE-DSS-CAMELLIA128-SHA256	DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256	Q
0x030000BE	HIGH	weak	TLSv12	DH	RSA	CAMELLIA	128	SHA256	5932	DHE-RSA-CAMELLIA128-SHA256	DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256	Q
0x030000BF	HIGH	weak	TLSv12	DH	None	CAMELLIA	128	SHA256	5932	ADH-CAMELLIA128-SHA256	ADH_WITH_CAMELLIA_128_CBC_SHA256,DH_anon_WITH_CAMELLIA_128_CBC_SHA256	Q
0x030000C0	HIGH	weak	TLSv12	RSA	RSA	CAMELLIA	256	SHA256	5932	CAMELLIA256-SHA256,RSA-CAMELLIA256-SHA256	RSA_WITH_CAMELLIA_256_CBC_SHA256	Q
0x030000C1	HIGH	weak	TLSv12	DSS	DH	CAMELLIA	256	SHA256	5932	DH-DSS-CAMELLIA256-SHA256	DH_DSS_WITH_CAMELLIA_256_CBC_SHA256	Q
0x030000C2	HIGH	weak	TLSv12	RSA	DH	CAMELLIA	256	SHA256	5932	DH-RSA-CAMELLIA256-SHA256	DH_RSA_WITH_CAMELLIA_256_CBC_SHA256	Q
0x030000C3	HIGH	weak	TLSv12	DH	DSS	CAMELLIA	256	SHA256	5932	DHE-DSS-CAMELLIA256-SHA256	DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256	Q
0x030000C4	HIGH	weak	TLSv12	DH	RSA	CAMELLIA	256	SHA256	5932	DHE-RSA-CAMELLIA256-SHA256	DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256	Q
0x030000C5	HIGH	weak	TLSv12	DH	None	CAMELLIA	256	SHA256	5932	ADH-CAMELLIA256-SHA256	ADH_WITH_CAMELLIA_256_CBC_SHA256,DH_anon_WITH_CAMELLIA_256_CBC_SHA256	Q
0x030000C6	-?-	-?-	TLSv13	SM2	SM2	SM4GCM	128	SM3	8998	TLS13-SM4-GCM,SM4-GCM-SM3	TLS_SM4_GCM_SM3	-
0x030000C7	-?-	-?-	TLSv13	SM2	SM2	SM4CCM	128	SM3	8998	TLS13-SM4-CCM,SM4-CCM-SM3	TLS_SM4_CCM_SM3	-
0x03001301	HIGH	HIGH	TLSv13	any	any	AESGCM	128	AEAD	8446	TLS13-AES-128-GCM-SHA256,TLS13-AES128-GCM-SHA256,TLS_AES_128_GCM_SHA256	AES_128_GCM_SHA256,DTLS_AES_128_GCM_SHA256,TLS13_AES_128_GCM_SHA256	D,E,F,T
0x03001302	HIGH	HIGH	TLSv13	any	any	AESGCM	256	AEAD	8446	TLS13-AES-256-GCM-SHA384,TLS13-AES256-GCM-SHA384,TLS_AES_256_GCM_SHA384	AES_256_GCM_SHA384,TLS13_AES_256_GCM_SHA384	D,E,F,T
0x03001303	HIGH	HIGH	TLSv13	any	any	ChaCha20-Poly1305	256	AEAD	8446	TLS13-CHACHA20-POLY1305-SHA256,TLS_CHACHA20_POLY1305_SHA256	CHACHA20_POLY1305_SHA256,TLS13_CHACHA20_POLY1305_SHA256	F,T
0x03001304	-?-	high	TLSv13	any	any	AESCCM	128	AEAD	8446	TLS13-AES-128-CCM-SHA256,TLS13-AES128-CCM-SHA256	AES_128_CCM_SHA256,TLS13_AES_128_CCM_SHA256	F,T
0x03001305	-?-	high	TLSv13	any	any	AESCCM	128	AEAD	8446	TLS13-AES-128-CCM8-SHA256,TLS13-AES128-CCM8-SHA256,TLS13-AES128-CCM-8-SHA256,TLS13-AES-128-CCM-8-SHA256	AES_128_CCM_8_SHA256,TLS13_AES_128_CCM_8_SHA256	F,T
0x03001306	-?-	-?-	TLSv13	-?-	-?-	AES	256	AEAD-256	aegis	AEGIS-256-SHA512,AEGIS-256-SHA384	AEGIS_256_SHA512,AEGIS_256_SHA384	U
# 03001306	-?-	-?-	TLSv13	-?-	-?-	AES	256	AEAD-256X2	aegis	AEGIS-256X2-SHA512	AEGIS_256X2_SHA512	-
0x03001307	-?-	-?-	TLSv13	-?-	-?-	AES	128	AEAD-128L	aegis	AEGIS-128L-SHA256	AEGIS_128L_SHA256	-
# 03001307	-?-	-?-	TLSv13	-?-	-?-	AES	128	AEAD-128X2	aegis	AEGIS-128X2-SHA256	AEGIS_128X2_SHA256	-
#     1306 and 1307 for DTLS13 also
0x030016B7	HIGH	HIGH	TLSv12	CECPQ1	RSA	ChaCha20-Poly1305	256	SHA256	-?-	CECPQ1-RSA-CHACHA20-POLY1305-SHA256	CECPQ1_RSA_WITH_CHACHA20_POLY1305_SHA256	O
0x030016B8	HIGH	HIGH	TLSv12	CECPQ1	ECDSA	ChaCha20-Poly1305	256	SHA256	-?-	CECPQ1-ECDSA-CHACHA20-POLY1305-SHA256	CECPQ1_ECDSA_WITH_CHACHA20_POLY1305_SHA256	O
0x030016B9	HIGH	HIGH	TLSv12	CECPQ1	RSA	AESGCM	256	SHA384	-?-	CECPQ1-RSA-AES256-GCM-SHA384	CECPQ1_RSA_WITH_AES_256_GCM_SHA384	O
0x030016BA	HIGH	HIGH	TLSv12	CECPQ1	ECDSA	AESGCM	256	SHA384	-?-	CECPQ1-ECDSA-AES256-GCM-SHA384	CECPQ1_ECDSA_WITH_AES_256_GCM_SHA384	O
0x0300C001	-?-	weak	SSLv3	ECDH/ECDSA	ECDH	None	0	SHA1	4492	ECDH-ECDSA-NULL-SHA	ECDH_ECDSA_WITH_NULL_SHA	-
0x0300C002	MEDIUM	weak	SSLv3	ECDH/ECDSA	ECDH	RC4	128	SHA1	4492,6347	ECDH-ECDSA-RC4-SHA	ECDH_ECDSA_WITH_RC4_128_SHA	-
0x0300C003	MEDIUM	weak	SSLv3	ECDH/ECDSA	ECDH	3DES	112	SHA1	4492	ECDH-ECDSA-DES-CBC3-SHA	ECDH_ECDSA_WITH_DES_192_CBC3_SHA,ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA	-
0x0300C004	HIGH	weak	SSLv3	ECDH/ECDSA	ECDH	AES	128	SHA1	4492	ECDH-ECDSA-AES128-SHA	ECDH_ECDSA_WITH_AES_128_CBC_SHA	-
0x0300C005	HIGH	weak	SSLv3	ECDH/ECDSA	ECDH	AES	256	SHA1	4492	ECDH-ECDSA-AES256-SHA	ECDH_ECDSA_WITH_AES_256_CBC_SHA	-
0x0300C006	-?-	weak	SSLv3	ECDH	ECDSA	None	0	SHA1	8422	ECDHE-ECDSA-NULL-SHA	ECDHE_ECDSA_WITH_NULL_SHA	-
0x0300C007	MEDIUM	weak	SSLv3	ECDH	ECDSA	RC4	128	SHA1	4492,6347	ECDHE-ECDSA-RC4-SHA	ECDHE_ECDSA_WITH_RC4_128_SHA	-
0x0300C008	MEDIUM	weak	SSLv3	ECDH	ECDSA	3DES	112	SHA1	8422	ECDHE-ECDSA-DES-CBC3-SHA	ECDHE_ECDSA_WITH_DES_192_CBC3_SHA,ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA	-
0x0300C009	HIGH	weak	SSLv3	ECDH	ECDSA	AES	128	SHA1	8422	ECDHE-ECDSA-AES128-SHA	ECDHE_ECDSA_WITH_AES_128_CBC_SHA	-
0x0300C00A	HIGH	weak	SSLv3	ECDH	ECDSA	AES	256	SHA1	8422	ECDHE-ECDSA-AES256-SHA	ECDHE_ECDSA_WITH_AES_256_CBC_SHA	-
0x0300C00B	-?-	weak	SSLv3	ECDH/RSA	ECDH	None	0	SHA1	4492	ECDH-RSA-NULL-SHA	ECDH_RSA_WITH_NULL_SHA	-
0x0300C00C	MEDIUM	weak	SSLv3	ECDH/RSA	ECDH	RC4	128	SHA1	4492,6347	ECDH-RSA-RC4-SHA	ECDH_RSA_WITH_RC4_128_SHA	-
0x0300C00D	MEDIUM	weak	SSLv3	ECDH/RSA	ECDH	3DES	112	SHA1	4492	ECDH-RSA-DES-CBC3-SHA	ECDH_RSA_WITH_DES_192_CBC3_SHA,ECDH_RSA_WITH_3DES_EDE_CBC_SHA	-
0x0300C00E	HIGH	weak	SSLv3	ECDH/RSA	ECDH	AES	128	SHA1	4492	ECDH-RSA-AES128-SHA	ECDH_RSA_WITH_AES_128_CBC_SHA	-
0x0300C00F	HIGH	weak	SSLv3	ECDH/RSA	ECDH	AES	256	SHA1	4492	ECDH-RSA-AES256-SHA	ECDH_RSA_WITH_AES_256_CBC_SHA	-
0x0300C010	-?-	weak	SSLv3	ECDH	RSA	None	0	SHA1	8422	ECDHE-RSA-NULL-SHA	ECDHE_RSA_WITH_NULL_SHA	-
0x0300C011	MEDIUM	weak	SSLv3	ECDH	RSA	RC4	128	SHA1	4492,6347	ECDHE-RSA-RC4-SHA	ECDHE_RSA_WITH_RC4_128_SHA	-
0x0300C012	MEDIUM	weak	SSLv3	ECDH	RSA	3DES	112	SHA1	8422	ECDHE-RSA-DES-CBC3-SHA	ECDHE_RSA_WITH_DES_192_CBC3_SHA,ECDHE_RSA_WITH_3DES_EDE_CBC_SHA	-
0x0300C013	HIGH	weak	SSLv3	ECDH	RSA	AES	128	SHA1	8422	ECDHE-RSA-AES128-SHA	ECDHE_RSA_WITH_AES_128_CBC_SHA	-
0x0300C014	HIGH	weak	SSLv3	ECDH	RSA	AES	256	SHA1	8422	ECDHE-RSA-AES256-SHA	ECDHE_RSA_WITH_AES_256_CBC_SHA	-
0x0300C015	-?-	weak	SSLv3	ECDH	None	None	0	SHA1	8422	AECDH-NULL-SHA	ECDH_anon_WITH_NULL_SHA,ECDH_anon_NULL_WITH_SHA	T
0x0300C016	MEDIUM	weak	SSLv3	ECDH	None	RC4	128	SHA1	4492,6347	AECDH-RC4-SHA	ECDH_anon_WITH_RC4_128_SHA,ECDH_anon_WITH_RC4_128_SHA	T
0x0300C017	MEDIUM	weak	SSLv3	ECDH	None	3DES	112	SHA1	8422	AECDH-DES-CBC3-SHA	ECDH_anon_WITH_DES_192_CBC3_SHA,ECDH_anon_WITH_3DES_EDE_CBC_SHA	-
0x0300C018	HIGH	weak	SSLv3	ECDH	None	AES	128	SHA1	8422	AECDH-AES128-SHA	ECDH_anon_WITH_AES_128_CBC_SHA	-
0x0300C019	HIGH	weak	SSLv3	ECDH	None	AES	256	SHA1	8422	AECDH-AES256-SHA	ECDH_anon_WITH_AES_256_CBC_SHA	-
0x0300C01A	MEDIUM	weak	SSLv3	SRP	None	3DES	112	SHA1	5054	SRP-3DES-EDE-CBC-SHA	SRP_SHA_WITH_3DES_EDE_CBC_SHA	L
0x0300C01B	MEDIUM	weak	SSLv3	SRP	RSA	3DES	112	SHA1	5054	SRP-RSA-3DES-EDE-CBC-SHA	SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA	L
0x0300C01C	MEDIUM	weak	SSLv3	SRP	DSS	3DES	112	SHA1	5054	SRP-DSS-3DES-EDE-CBC-SHA	SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA	L
0x0300C01D	HIGH	weak	SSLv3	SRP	None	AES	128	SHA1	5054	SRP-AES-128-CBC-SHA	SRP_SHA_WITH_AES_128_CBC_SHA	L
0x0300C01E	HIGH	weak	SSLv3	SRP	RSA	AES	128	SHA1	5054	SRP-RSA-AES-128-CBC-SHA	SRP_SHA_RSA_WITH_AES_128_CBC_SHA	L
0x0300C01F	HIGH	weak	SSLv3	SRP	DSS	AES	128	SHA1	5054	SRP-DSS-AES-128-CBC-SHA	SRP_SHA_DSS_WITH_AES_128_CBC_SHA	L
0x0300C020	HIGH	weak	SSLv3	SRP	None	AES	256	SHA1	5054	SRP-AES-256-CBC-SHA	SRP_SHA_WITH_AES_256_CBC_SHA	L
0x0300C021	HIGH	weak	SSLv3	SRP	RSA	AES	256	SHA1	5054	SRP-RSA-AES-256-CBC-SHA	SRP_SHA_RSA_WITH_AES_256_CBC_SHA	L
0x0300C022	HIGH	weak	SSLv3	SRP	DSS	AES	256	SHA1	5054	SRP-DSS-AES-256-CBC-SHA	SRP_SHA_DSS_WITH_AES_256_CBC_SHA	L
0x0300C023	HIGH	weak	TLSv12	ECDH	ECDSA	AES	128	SHA256	5289	ECDHE-ECDSA-AES128-SHA256	ECDHE_ECDSA_WITH_AES_128_SHA256,ECDHE_ECDSA_WITH_AES_128_CBC_SHA256	L
0x0300C024	HIGH	weak	TLSv12	ECDH	ECDSA	AES	256	SHA384	5289	ECDHE-ECDSA-AES256-SHA384	ECDHE_ECDSA_WITH_AES_256_SHA384,ECDHE_ECDSA_WITH_AES_256_CBC_SHA384	L
0x0300C025	HIGH	weak	TLSv12	ECDH/ECDSA	ECDH	AES	128	SHA256	5289	ECDH-ECDSA-AES128-SHA256	ECDH_ECDSA_WITH_AES_128_SHA256,ECDH_ECDSA_WITH_AES_128_CBC_SHA256	L
0x0300C026	HIGH	weak	TLSv12	ECDH/ECDSA	ECDH	AES	256	SHA384	5289	ECDH-ECDSA-AES256-SHA384	ECDH_ECDSA_WITH_AES_256_SHA384,ECDH_ECDSA_WITH_AES_256_CBC_SHA384	L
0x0300C027	HIGH	weak	TLSv12	ECDH	RSA	AES	128	SHA256	5289	ECDHE-RSA-AES128-SHA256	ECDHE_RSA_WITH_AES_128_SHA256,ECDHE_RSA_WITH_AES_128_CBC_SHA256	L
0x0300C028	HIGH	weak	TLSv12	ECDH	RSA	AES	256	SHA384	5289	ECDHE-RSA-AES256-SHA384	ECDHE_RSA_WITH_AES_256_SHA384,ECDHE_RSA_WITH_AES_256_CBC_SHA384	L
0x0300C029	HIGH	weak	TLSv12	ECDH/RSA	ECDH	AES	128	SHA256	5289	ECDH-RSA-AES128-SHA256	ECDH_RSA_WITH_AES_128_SHA256,ECDH_RSA_WITH_AES_128_CBC_SHA256	L
0x0300C02A	HIGH	weak	TLSv12	ECDH/RSA	ECDH	AES	256	SHA384	5289	ECDH-RSA-AES256-SHA384	ECDH_RSA_WITH_AES_256_SHA384,ECDH_RSA_WITH_AES_256_CBC_SHA384	L
0x0300C02B	HIGH	HIGH	TLSv12	ECDH	ECDSA	AESGCM	128	AEAD	5289	ECDHE-ECDSA-AES128-GCM-SHA256	ECDHE_ECDSA_WITH_AES_128_GCM_SHA256	L
0x0300C02C	HIGH	HIGH	TLSv12	ECDH	ECDSA	AESGCM	256	AEAD	5289	ECDHE-ECDSA-AES256-GCM-SHA384	ECDHE_ECDSA_WITH_AES_256_GCM_SHA384	L
0x0300C02D	HIGH	HIGH	TLSv12	ECDH/ECDSA	ECDH	AESGCM	128	AEAD	5289	ECDH-ECDSA-AES128-GCM-SHA256	ECDH_ECDSA_WITH_AES_128_GCM_SHA256	L
0x0300C02E	HIGH	HIGH	TLSv12	ECDH/ECDSA	ECDH	AESGCM	256	AEAD	5289	ECDH-ECDSA-AES256-GCM-SHA384	ECDH_ECDSA_WITH_AES_256_GCM_SHA384	L
0x0300C02F	HIGH	HIGH	TLSv12	ECDH	RSA	AESGCM	128	AEAD	5289,8442	ECDHE-RSA-AES128-GCM-SHA256	ECDHE_RSA_WITH_AES_128_GCM_SHA256	L
0x0300C030	HIGH	HIGH	TLSv12	ECDH	RSA	AESGCM	256	AEAD	5289,8442	ECDHE-RSA-AES256-GCM-SHA384	ECDHE_RSA_WITH_AES_256_GCM_SHA384	L
0x0300C031	HIGH	HIGH	TLSv12	ECDH/RSA	ECDH	AESGCM	128	AEAD	5289	ECDH-RSA-AES128-GCM-SHA256	ECDH_RSA_WITH_AES_128_GCM_SHA256	L
0x0300C032	HIGH	HIGH	TLSv12	ECDH/RSA	ECDH	AESGCM	256	AEAD	5289	ECDH-RSA-AES256-GCM-SHA384	ECDH_RSA_WITH_AES_256_GCM_SHA384	L
0x0300C033	-?-	medium	TLSv12	ECDHEPSK	PSK	RC4	128	SHA1	5489,6347	ECDHE-PSK-RC4-SHA,ECDHE-PSK-RC4-128-SHA	ECDHE_PSK_WITH_RC4_128_SHA	-
0x0300C034	-?-	medium	TLSv12	ECDHEPSK	PSK	3DES	192	SHA1	5489	ECDHE-PSK-3DES-SHA,ECDHE-PSK-3DES-EDE-CBC-SHA	ECDHE_PSK_WITH_3DES_EDE_CBC_SHA	-
0x0300C035	HIGH	medium	TLSv1	ECDHEPSK	PSK	AES	128	SHA1	5489	ECDHE-PSK-AES128-SHA,ECDHE-PSK-AES128-CBC-SHA	ECDHE_PSK_WITH_AES_128_CBC_SHA	-
0x0300C036	HIGH	medium	TLSv12	ECDHEPSK	PSK	AES	256	SHA1	5489	ECDHE-PSK-AES256-SHA,ECDHE-PSK-AES256-CBC-SHA	ECDHE_PSK_WITH_AES_256_CBC_SHA	-
0x0300C037	HIGH	medium	TLSv1	ECDHEPSK	PSK	AES	128	SHA256	5489	ECDHE-PSK-AES128-SHA256,ECDHE-PSK-AES128-CBC-SHA256	ECDHE_PSK_WITH_AES_128_CBC_SHA256	-
0x0300C038	HIGH	medium	TLSv1	ECDHEPSK	PSK	AES	256	SHA384	5489	ECDHE-PSK-AES256-SHA384,ECDHE-PSK-AES256-CBC-SHA384	ECDHE_PSK_WITH_AES_256_CBC_SHA384	-
0x0300C039	-?-	weak	TLSv1	ECDHEPSK	PSK	None	0	SHA1	5489	ECDHE-PSK-SHA,ECDHE-PSK-NULL-SHA	ECDHE_PSK_WITH_NULL_SHA	-
0x0300C03A	-?-	weak	TLSv1	ECDHEPSK	PSK	None	0	SHA1	5489	ECDHE-PSK-SHA256,ECDHE-PSK-NULL-SHA256	ECDHE_PSK_WITH_NULL_SHA256	-
0x0300C03B	-?-	weak	TLSv1	ECDHEPSK	PSK	None	0	SHA1	5489	ECDHE-PSK-SHA384,ECDHE-PSK-NULL-SHA384	ECDHE_PSK_WITH_NULL_SHA384	-
0x0300C03C	-?-	weak	TLSv12	RSA	RSA	ARIA	128	SHA256	6209	RSA-ARIA128-SHA256	RSA_WITH_ARIA_128_CBC_SHA256	-
0x0300C03D	-?-	weak	TLSv12	RSA	RSA	ARIA	256	SHA384	6209	RSA-ARIA256-SHA384	RSA_WITH_ARIA_256_CBC_SHA384	-
0x0300C03E	-?-	weak	TLSv12	DH	DSS	ARIA	128	SHA256	6209	DH-DSS-ARIA128-SHA256	DH_DSS_WITH_ARIA_128_CBC_SHA256	-
0x0300C03F	-?-	weak	TLSv12	DH	DSS	ARIA	256	SHA384	6209	DH-DSS-ARIA256-SHA384	DH_DSS_WITH_ARIA_256_CBC_SHA384	-
0x0300C040	-?-	weak	TLSv12	DH	RSA	ARIA	128	SHA256	6209	DH-RSA-ARIA128-SHA256	DH_RSA_WITH_ARIA_128_CBC_SHA256	-
0x0300C041	-?-	weak	TLSv12	DH	RSA	ARIA	256	SHA384	6209	DH-RSA-ARIA256-SHA384	DH_RSA_WITH_ARIA_256_CBC_SHA384	-
0x0300C042	-?-	weak	TLSv12	DHE	DSS	ARIA	128	SHA256	6209	DHE-DSS-ARIA128-SHA256	DHE_DSS_WITH_ARIA_128_CBC_SHA256	-
0x0300C043	-?-	weak	TLSv12	DHE	DSS	ARIA	256	SHA384	6209	DHE-DSS-ARIA256-SHA384	DHE_DSS_WITH_ARIA_256_CBC_SHA384	-
0x0300C044	-?-	weak	TLSv12	DHE	RSA	ARIA	128	SHA256	6209	DHE-RSA-ARIA128-SHA256,DHE-RSA-ARIA256-SHA256	DHE_RSA_WITH_ARIA_256_CBC_SHA256	I
0x0300C045	-?-	weak	TLSv12	DHE	RSA	ARIA	256	SHA384	6209	DHE-RSA-ARIA256-SHA384	DHE_RSA_WITH_ARIA_256_CBC_SHA384	-
0x0300C046	-?-	weak	TLSv12	DH	None	ARIA	128	SHA256	6209	ADH-ARIA128-SHA256	DH_anon_WITH_ARIA_128_CBC_SHA256	-
0x0300C047	-?-	weak	TLSv12	DH	None	ARIA	256	SHA384	6209	ADH-ARIA256-SHA384	DH_anon_WITH_ARIA_256_CBC_SHA384	-
0x0300C048	-?-	weak	TLSv12	ECDHE	ECDSA	ARIA	128	SHA256	6209	ECDHE-ECDSA-ARIA128-SHA256	ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256	-
0x0300C049	-?-	weak	TLSv12	ECDHE	ECDSA	ARIA	256	SHA384	6209	ECDHE-ECDSA-ARIA256-SHA384	ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384	-
0x0300C04A	-?-	weak	TLSv12	ECDH	ECDSA	ARIA	128	SHA256	6209	ECDH-ECDSA-ARIA128-SHA256	ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256	-
0x0300C04B	-?-	weak	TLSv12	ECDH	ECDSA	ARIA	256	SHA384	6209	ECDH-ECDSA-ARIA256-SHA384	ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384	-
0x0300C04C	-?-	weak	TLSv12	ECDHE	RSA	ARIA	128	SHA256	6209	ECDHE-RSA-ARIA128-SHA256	ECDHE_RSA_WITH_ARIA_128_CBC_SHA256	-
0x0300C04D	-?-	weak	TLSv12	ECDHE	RSA	ARIA	256	SHA384	6209	ECDHE-RSA-ARIA256-SHA384	ECDHE_RSA_WITH_ARIA_256_CBC_SHA384	-
0x0300C04E	-?-	weak	TLSv12	ECDH	RSA	ARIA	128	SHA256	6209	ECDH-RSA-ARIA128-SHA256	ECDH_RSA_WITH_ARIA_128_CBC_SHA256	-
0x0300C04F	-?-	weak	TLSv12	ECDH	RSA	ARIA	256	SHA384	6209	ECDH-RSA-ARIA256-SHA384	ECDH_RSA_WITH_ARIA_256_CBC_SHA384	-
0x0300C050	HIGH	HIGH	TLSv12	RSA	RSA	ARIAGCM	128	AEAD	6209	RSA-ARIA128-GCM-SHA256,ARIA128-GCM-SHA256	RSA_WITH_ARIA_128_GCM_SHA256	-
0x0300C051	HIGH	HIGH	TLSv12	RSA	RSA	ARIAGCM	256	AEAD	6209	RSA-ARIA256-GCM-SHA384,ARIA256-GCM-SHA384	RSA_WITH_ARIA_256_GCM_SHA384	-
0x0300C052	HIGH	HIGH	TLSv12	DH	RSA	ARIAGCM	128	AEAD	6209	DHE-RSA-ARIA128-GCM-SHA256	DHE_RSA_WITH_ARIA_128_GCM_SHA256	-
0x0300C053	HIGH	HIGH	TLSv12	DH	RSA	ARIAGCM	256	AEAD	6209	DHE-RSA-ARIA256-GCM-SHA384	DHE_RSA_WITH_ARIA_256_GCM_SHA384	-
0x0300C054	-?-	-?-	TLSv12	DH	RSA	ARIAGCM	128	AEAD	6209	DH-RSA-ARIA128-GCM-SHA256	DH_RSA_WITH_ARIA_128_GCM_SHA256	-
0x0300C055	-?-	-?-	TLSv12	DH	RSA	ARIAGCM	256	AEAD	6209	DH-RSA-ARIA256-GCM-SHA384	DH_RSA_WITH_ARIA_256_GCM_SHA384	-
0x0300C056	HIGH	HIGH	TLSv12	DH	DSS	ARIAGCM	128	AEAD	6209	DHE-DSS-ARIA128-GCM-SHA256	DHE_DSS_WITH_ARIA_128_GCM_SHA256	-
0x0300C057	HIGH	HIGH	TLSv12	DH	DSS	ARIAGCM	256	AEAD	6209	DHE-DSS-ARIA256-GCM-SHA384	DHE_DSS_WITH_ARIA_256_GCM_SHA384	-
0x0300C058	-?-	-?-	TLSv12	DH	DSS	ARIAGCM	128	AEAD	6209	DH-DSS-ARIA128-GCM-SHA256	DH_DSS_WITH_ARIA_128_GCM_SHA256	-
0x0300C059	-?-	-?-	TLSv12	DH	DSS	ARIAGCM	256	AEAD	6209	DH-DSS-ARIA256-GCM-SHA384	DH_DSS_WITH_ARIA_256_GCM_SHA384	-
0x0300C05A	-?-	-?-	TLSv12	DH	None	ARIAGCM	128	AEAD	6209	ADH-ARIA128-GCM-SHA256	DH_anon_WITH_ARIA_128_GCM_SHA256	-
0x0300C05B	-?-	-?-	TLSv12	DH	None	ARIAGCM	256	AEAD	6209	ADH-ARIA256-GCM-SHA384	DH_anon_WITH_ARIA_256_GCM_SHA384	-
0x0300C05C	HIGH	HIGH	TLSv12	ECDH	ECDSA	ARIAGCM	128	AEAD	6209	ECDHE-ECDSA-ARIA128-GCM-SHA256	ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256	-
0x0300C05D	HIGH	HIGH	TLSv12	ECDH	ECDSA	ARIAGCM	256	AEAD	6209	ECDHE-ECDSA-ARIA256-GCM-SHA384	ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384	-
0x0300C05E	-?-	-?-	TLSv12	ECDH	ECDSA	ARIAGCM	128	AEAD	6209	ECDH-ECDSA-ARIA128-GCM-SHA256	ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256	-
0x0300C05F	-?-	-?-	TLSv12	ECDH	ECDSA	ARIAGCM	256	AEAD	6209	ECDH-ECDSA-ARIA256-GCM-SHA384	ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384	-
0x0300C060	HIGH	HIGH	TLSv12	ECDH	RSA	ARIAGCM	128	AEAD	6209	ECDHE-RSA-ARIA128-GCM-SHA256,ECDHE-ARIA128-GCM-SHA256	ECDHE_RSA_WITH_ARIA_128_GCM_SHA256	-
0x0300C061	HIGH	HIGH	TLSv12	ECDH	RSA	ARIAGCM	256	AEAD	6209	ECDHE-RSA-ARIA256-GCM-SHA384,ECDHE-ARIA256-GCM-SHA384	ECDHE_RSA_WITH_ARIA_256_GCM_SHA384	-
0x0300C062	-?-	high	TLSv12	ECDH	RSA	ARIAGCM	128	AEAD	6209	ECDH-RSA-ARIA128-GCM-SHA256,ECDH-ARIA128-GCM-SHA256	ECDH_RSA_WITH_ARIA_128_GCM_SHA256	-
0x0300C063	-?-	high	TLSv12	ECDH	RSA	ARIAGCM	256	AEAD	6209	ECDH-RSA-ARIA256-GCM-SHA384,ECDH-ARIA256-GCM-SHA384	ECDH_RSA_WITH_ARIA_256_GCM_SHA384	-
0x0300C064	HIGH	medium	TLSv12	PSK	PSK	ARIA	128	SHA256	6209	PSK-ARIA128-SHA256	PSK_WITH_ARIA_128_CBC_SHA256	-
0x0300C065	HIGH	medium	TLSv12	PSK	PSK	ARIA	256	SHA384	6209	PSK-ARIA256-SHA384	PSK_WITH_ARIA_256_CBC_SHA384	-
0x0300C066	-?-	medium	TLSv12	DHE	PSK	ARIA	128	SHA256	6209	DHE-PSK-ARIA128-SHA256	DHE_PSK_WITH_ARIA_128_CBC_SHA256	-
0x0300C067	-?-	medium	TLSv12	DHE	PSK	ARIA	256	SHA384	6209	DHE-PSK-ARIA256-SHA384	DHE_PSK_WITH_ARIA_256_CBC_SHA384	-
0x0300C068	-?-	medium	TLSv12	RSA	PSK	ARIA	128	SHA256	6209	RSA-PSK-ARIA128-SHA256	RSA_PSK_WITH_ARIA_128_CBC_SHA256	-
0x0300C069	-?-	medium	TLSv12	RSA	PSK	ARIA	256	SHA384	6209	RSA-PSK-ARIA256-SHA384	RSA_PSK_WITH_ARIA_256_CBC_SHA384	-
0x0300C06A	HIGH	HIGH	TLSv12	PSK	PSK	ARIAGCM	128	AEAD	6209	PSK-ARIA128-GCM-SHA256	PSK_WITH_ARIA_128_GCM_SHA256	-
0x0300C06B	HIGH	HIGH	TLSv12	PSK	PSK	ARIAGCM	256	AEAD	6209	PSK-ARIA256-GCM-SHA384	PSK_WITH_ARIA_256_GCM_SHA384	-
0x0300C06C	HIGH	HIGH	TLSv12	DHEPSK	PSK	ARIAGCM	128	AEAD	6209	DHE-PSK-ARIA128-GCM-SHA256	DHE_PSK_WITH_ARIA_128_GCM_SHA256	-
0x0300C06D	HIGH	HIGH	TLSv12	DHEPSK	PSK	ARIAGCM	256	AEAD	6209	DHE-PSK-ARIA256-GCM-SHA384	DHE_PSK_WITH_ARIA_256_GCM_SHA384	-
0x0300C06E	HIGH	HIGH	TLSv12	RSAPSK	RSA	ARIAGCM	128	AEAD	6209	RSA-PSK-ARIA128-GCM-SHA256	RSA_PSK_WITH_ARIA_128_GCM_SHA256	-
0x0300C06F	HIGH	HIGH	TLSv12	RSAPSK	PSK	ARIAGCM	256	AEAD	6209	RSA-PSK-ARIA256-GCM-SHA384	RSA_PSK_WITH_ARIA_256_GCM_SHA384	-
0x0300C070	-?-	medium	TLSv12	ECDHE	PSK	ARIA	128	SHA256	6209	ECDHE-PSK-ARIA128-SHA256	ECDHE_PSK_WITH_ARIA_128_CBC_SHA256	-
0x0300C071	-?-	medium	TLSv12	ECDHE	PSK	ARIA	256	SHA384	6209	ECDHE-PSK-ARIA256-SHA384	ECDHE_PSK_WITH_ARIA_256_CBC_SHA384	-
0x0300C072	HIGH	weak	TLSv12	ECDH	ECDSA	CAMELLIA	128	SHA256	6367	ECDHE-ECDSA-CAMELLIA128-SHA256	ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256	-
0x0300C073	HIGH	weak	TLSv12	ECDH	ECDSA	CAMELLIA	256	SHA384	6367	ECDHE-ECDSA-CAMELLIA256-SHA384	ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384	-
0x0300C074	HIGH	weak	TLSv12	ECDH/ECDSA	ECDH	CAMELLIA	128	SHA256	6367	ECDH-ECDSA-CAMELLIA128-SHA256	ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256	-
0x0300C075	HIGH	weak	TLSv12	ECDH/ECDSA	ECDH	CAMELLIA	256	SHA384	6367	ECDH-ECDSA-CAMELLIA256-SHA384	ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384	-
0x0300C076	HIGH	weak	TLSv12	ECDH	RSA	CAMELLIA	128	SHA256	6367	ECDHE-RSA-CAMELLIA128-SHA256	ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256	-
0x0300C077	HIGH	weak	TLSv12	ECDH	RSA	CAMELLIA	256	SHA384	6367	ECDHE-RSA-CAMELLIA256-SHA384	ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384	-
0x0300C078	HIGH	weak	TLSv12	ECDH/RSA	ECDH	CAMELLIA	128	SHA256	6367	ECDH-RSA-CAMELLIA128-SHA256	ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256	-
0x0300C079	HIGH	weak	TLSv12	ECDH/RSA	ECDH	CAMELLIA	256	SHA384	6367	ECDH-RSA-CAMELLIA256-SHA384	ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384	-
0x0300C07A	HIGH	HIGH	TLSv12	RSA	RSA	CAMELLIAGCM	128	SHA256	6367	RSA-CAMELLIA128-GCM-SHA256	RSA_WITH_CAMELLIA_128_GCM_SHA256	-
0x0300C07B	HIGH	HIGH	TLSv12	RSA	RSA	CAMELLIAGCM	256	SHA384	6367	RSA-CAMELLIA256-GCM-SHA384	RSA_WITH_CAMELLIA_256_GCM_SHA384	-
0x0300C07C	HIGH	HIGH	TLSv12	RSA	DHE	CAMELLIAGCM	128	SHA256	6367	DHE-RSA-CAMELLIA128-GCM-SHA256	DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256	-
0x0300C07D	HIGH	HIGH	TLSv12	RSA	DHE	CAMELLIAGCM	256	SHA384	6367	DHE-RSA-CAMELLIA256-GCM-SHA384	DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384	-
0x0300C07E	HIGH	HIGH	TLSv12	RSA	DH	CAMELLIAGCM	128	SHA256	6367	DH-RSA-CAMELLIA128-GCM-SHA256	DH_RSA_WITH_CAMELLIA_128_GCM_SHA256	-
0x0300C07F	HIGH	HIGH	TLSv12	RSA	DH	CAMELLIAGCM	256	SHA384	6367	DH-RSA-CAMELLIA256-GCM-SHA384	DH_RSA_WITH_CAMELLIA_256_GCM_SHA384	-
0x0300C080	HIGH	HIGH	TLSv12	DSS	DHE	CAMELLIAGCM	128	SHA256	6367	DHE-DSS-CAMELLIA128-GCM-SHA256	DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256	-
0x0300C081	HIGH	HIGH	TLSv12	DSS	DHE	CAMELLIAGCM	256	SHA384	6367	DHE-DSS-CAMELLIA256-GCM-SHA384	DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384	-
0x0300C082	HIGH	HIGH	TLSv12	DSS	DH	CAMELLIAGCM	128	SHA256	6367	DH-DSS-CAMELLIA128-GCM-SHA256	DH_DSS_WITH_CAMELLIA_128_GCM_SHA256	-
0x0300C083	HIGH	HIGH	TLSv12	DSS	DH	CAMELLIAGCM	256	SHA384	6367	DH-DSS-CAMELLIA256-GCM-SHA384	DH_DSS_WITH_CAMELLIA_256_GCM_SHA384	-
0x0300C084	HIGH	HIGH	TLSv12	DSS	ADH	CAMELLIAGCM	128	SHA256	6367	ADH-DSS-CAMELLIA128-GCM-SHA256	DH_anon_DSS_WITH_CAMELLIA_128_GCM_SHA256,DH_anon_WITH_CAMELLIA_128_GCM_SHA256	-
0x0300C085	HIGH	HIGH	TLSv12	DSS	ADH	CAMELLIAGCM	256	SHA384	6367	ADH-DSS-CAMELLIA256-GCM-SHA384	DH_anon_DSS_WITH_CAMELLIA_256_GCM_SHA384,DH_anon_WITH_CAMELLIA_256_GCM_SHA384	-
0x0300C086	HIGH	HIGH	TLSv12	ECDH	ECDHE	CAMELLIAGCM	128	SHA256	6367	ECDHE-ECDSA-CAMELLIA128-GCM-SHA256	ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256	-
0x0300C087	HIGH	HIGH	TLSv12	ECDH	ECDHE	CAMELLIAGCM	256	SHA384	6367	ECDHE-ECDSA-CAMELLIA256-GCM-SHA384	ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384	-
0x0300C088	HIGH	HIGH	TLSv12	ECDH	ECDH	CAMELLIAGCM	128	SHA256	6367	ECDH-ECDSA-CAMELLIA128-GCM-SHA256	ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256	-
0x0300C089	HIGH	HIGH	TLSv12	ECDH	ECDH	CAMELLIAGCM	256	SHA384	6367	ECDH-ECDSA-CAMELLIA256-GCM-SHA384	ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384	-
0x0300C08A	HIGH	HIGH	TLSv12	RSA	ECDHE	CAMELLIAGCM	128	SHA256	6367	ECDHE-RSA-CAMELLIA128-GCM-SHA256	ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256	-
0x0300C08B	HIGH	HIGH	TLSv12	RSA	ECDHE	CAMELLIAGCM	256	SHA384	6367	ECDHE-RSA-CAMELLIA256-GCM-SHA384	ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384	-
0x0300C08C	HIGH	HIGH	TLSv12	RSA	ECDH	CAMELLIAGCM	128	SHA256	6367	ECDH-RSA-CAMELLIA128-GCM-SHA256	ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256	-
0x0300C08D	HIGH	HIGH	TLSv12	RSA	ECDH	CAMELLIAGCM	256	SHA384	6367	ECDH-RSA-CAMELLIA256-GCM-SHA384	ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384	-
0x0300C08E	HIGH	HIGH	TLSv12	PSK	RSA	CAMELLIAGCM	128	SHA256	6367	PSK-CAMELLIA128-GCM-SHA256	PSK_WITH_CAMELLIA_128_GCM_SHA256	-
0x0300C08F	HIGH	HIGH	TLSv12	PSK	RSA	CAMELLIAGCM	256	SHA384	6367	PSK-CAMELLIA256-GCM-SHA384	PSK_WITH_CAMELLIA_256_GCM_SHA384	-
0x0300C090	HIGH	HIGH	TLSv12	PSK	DHE	CAMELLIAGCM	128	SHA256	6367	DHE-PSK-CAMELLIA128-GCM-SHA256	DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256	-
0x0300C091	HIGH	HIGH	TLSv12	PSK	DHE	CAMELLIAGCM	256	SHA384	6367	DHE-PSK-CAMELLIA256-GCM-SHA384	DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384	-
0x0300C092	HIGH	HIGH	TLSv12	PSK	RSA	CAMELLIAGCM	128	SHA256	6367	RSA-PSK-CAMELLIA128-GCM-SHA256	RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256	-
0x0300C093	HIGH	HIGH	TLSv12	PSK	RSA	CAMELLIAGCM	256	SHA384	6367	RSA-PSK-CAMELLIA256-GCM-SHA384	RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384	-
0x0300C094	HIGH	medium	TLSv12	PSK	PSK	CAMELLIA	128	SHA256	6367	PSK-CAMELLIA128-SHA256	PSK_WITH_CAMELLIA_128_CBC_SHA256	-
0x0300C095	HIGH	medium	TLSv12	PSK	PSK	CAMELLIA	256	SHA384	6367	PSK-CAMELLIA256-SHA384	PSK_WITH_CAMELLIA_256_CBC_SHA384	-
0x0300C096	HIGH	medium	TLSv12	PSK	DHE	CAMELLIA	128	SHA256	6367	DHE-PSK-CAMELLIA128-SHA256	DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256	-
0x0300C097	HIGH	medium	TLSv12	PSK	DHE	CAMELLIA	256	SHA384	6367	DHE-PSK-CAMELLIA256-SHA384	DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384	-
0x0300C098	HIGH	medium	TLSv12	PSK	RSA	CAMELLIA	128	SHA256	6367	RSA-PSK-CAMELLIA128-SHA256	RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256	-
0x0300C099	HIGH	medium	TLSv12	PSK	RSA	CAMELLIA	256	SHA384	6367	RSA-PSK-CAMELLIA256-SHA384	RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384	-
0x0300C09A	HIGH	medium	TLSv12	PSK	ECDHE	CAMELLIA	128	SHA256	6367	ECDHE-PSK-CAMELLIA128-SHA256	ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256	-
0x0300C09B	HIGH	medium	TLSv12	PSK	ECDHE	CAMELLIA	256	SHA384	6367	ECDHE-PSK-CAMELLIA256-SHA384	ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384	-
0x0300C09C	HIGH	HIGH	TLSv12	RSA	RSA	AESCCM	128	AEAD	6655	RSA-AES128-CCM,AES128-CCM	RSA_WITH_AES_128_CCM	-
0x0300C09D	HIGH	HIGH	TLSv12	RSA	RSA	AESCCM	256	AEAD	6655	RSA-AES256-CCM,AES256-CCM	RSA_WITH_AES_256_CCM	-
0x0300C09E	HIGH	HIGH	TLSv12	DH	RSA	AESCCM	128	AEAD	6655	DHE-RSA-AES128-CCM	DHE_RSA_WITH_AES_128_CCM	-
0x0300C09F	HIGH	HIGH	TLSv12	DH	RSA	AESCCM	256	AEAD	6655	DHE-RSA-AES256-CCM	DHE_RSA_WITH_AES_256_CCM	-
0x0300C0A0	HIGH	HIGH	TLSv12	RSA	RSA	AESCCM8	128	AEAD	6655	RSA-AES128-CCM8,AES128-CCM8,RSA-AES128-CCM-8	RSA_WITH_AES_128_CCM_8	-
0x0300C0A1	HIGH	HIGH	TLSv12	RSA	RSA	AESCCM8	256	AEAD	6655	RSA-AES256-CCM8,AES256-CCM8,RSA-AES256-CCM-8	RSA_WITH_AES_256_CCM_8	-
0x0300C0A2	HIGH	HIGH	TLSv12	DH	RSA	AESCCM8	128	AEAD	6655	DHE-RSA-AES128-CCM8,DHE-RSA-AES128-CCM-8	DHE_RSA_WITH_AES_128_CCM_8	-
0x0300C0A3	HIGH	HIGH	TLSv12	DH	RSA	AESCCM8	256	AEAD	6655	DHE-RSA-AES256-CCM8,DHE-RSA-AES256-CCM-8	DHE_RSA_WITH_AES_256_CCM_8	-
0x0300C0A4	HIGH	HIGH	TLSv12	PSK	PSK	AESCCM	128	AEAD	6655	PSK-AES128-CCM,PSK-RSA-AES128-CCM	PSK_WITH_AES_128_CCM	-
0x0300C0A5	HIGH	HIGH	TLSv12	PSK	PSK	AESCCM	256	AEAD	6655	PSK-AES256-CCM,PSK-RSA-AES256-CCM	PSK_WITH_AES_256_CCM	-
0x0300C0A6	HIGH	high	TLSv12	DHE	RSA	AESGCM	128	AEAD	6655	DHE-PSK-AES128-CCM,DHE-PSK-RSA-AES128-CCM	DHE_PSK_WITH_AES_128_CCM	-
0x0300C0A7	HIGH	high	TLSv12	DHE	RSA	AESGCM	256	AEAD	6655	DHE-PSK-AES256-CCM,DHE-PSK-RSA-AES256-CCM	DHE_PSK_WITH_AES_256_CCM	-
0x0300C0A8	HIGH	HIGH	TLSv12	PSK	PSK	AESCCM8	128	AEAD	6655	PSK-AES128-CCM8,PSK-AES128-CCM-8,PSK-RSA-AES128-CCM-8	PSK_WITH_AES_128_CCM_8	-
0x0300C0A9	HIGH	HIGH	TLSv12	PSK	PSK	AESCCM8	256	AEAD	6655	PSK-AES256-CCM8,PSK-AES256-CCM-8,PSK-RSA-AES256-CCM-8	PSK_WITH_AES_256_CCM_8	-
0x0300C0AA	HIGH	HIGH	TLSv12	DHEPSK	PSK	AESGCM8	128	AEAD	6655	DHE-PSK-AES128-CCM8,PSK-DHE-AES128-CCM8,DHE-PSK-AES128-CCM-8	DHE_PSK_WITH_AES_128_CCM_8,PSK_DHE_WITH_AES_128_CCM_8	FIXME
0x0300C0AB	HIGH	HIGH	TLSv12	DHEPSK	PSK	AESGCM8	256	AEAD	6655	DHE-PSK-AES256-CCM8,PSK-DHE-AES256-CCM8,DHE-PSK-AES256-CCM-8	DHE_PSK_WITH_AES_256_CCM_8,PSK_DHE_WITH_AES_256_CCM_8	FIXME
0x0300C0AC	HIGH	HIGH	TLSv12	ECDH	ECDSA	AESCCM	128	AEAD	7251	ECDHE-ECDSA-AES128-CCM	ECDHE_ECDSA_WITH_AES_128_CCM	-
0x0300C0AD	HIGH	HIGH	TLSv12	ECDH	ECDSA	AESCCM	256	AEAD	7251	ECDHE-ECDSA-AES256-CCM	ECDHE_ECDSA_WITH_AES_256_CCM	-
0x0300C0AE	HIGH	HIGH	TLSv12	ECDH	ECDSA	AESCCM8	128	AEAD	7251	ECDHE-ECDSA-AES128-CCM8,ECDHE-ECDSA-AES128-CCM-8	ECDHE_ECDSA_WITH_AES_128_CCM_8	-
0x0300C0AF	HIGH	HIGH	TLSv12	ECDH	ECDSA	AESCCM8	256	AEAD	7251	ECDHE-ECDSA-AES256-CCM8,ECDHE-ECDSA-AES256-CCM-8	ECDHE_ECDSA_WITH_AES_256_CCM_8	-
0x0300C0B0	-?-	-?-	TLSv12	ECCPWD	RSA	AESGCM	128	AEAD	8492	ECCPWD-AES128-GCM-SHA256	ECCPWD_WITH_AES_128_GCM_SHA256	R
0x0300C0B1	-?-	-?-	TLSv12	ECCPWD	RSA	AESGCM	256	AEAD	8492	ECCPWD-AES256-GCM-SHA384	ECCPWD_WITH_AES_256_GCM_SHA384	R
0x0300C0B2	-?-	-?-	TLSv12	ECCPWD	RSA	AESCCM	128	AEAD	8492	ECCPWD-AES128-CCM-SHA256	ECCPWD_WITH_AES_128_CCM_SHA256	R
0x0300C0B3	-?-	-?-	TLSv12	ECCPWD	RSA	AESCCM	256	AEAD	8492	ECCPWD-AES256-CCM-SHA384	ECCPWD_WITH_AES_256_CCM_SHA384	R
0x0300C0B4	-?-	-?-	TLSv13	-?-	-?-	-?-	-?-	SHA256	9150	SHA256-SHA256,TLS13-SHA256-SHA256,TLS_SHA256_SHA256	SHA256_SHA256	-
0x0300C0B5	-?-	-?-	TLSv13	-?-	-?-	-?-	-?-	SHA384	9150	SHA384-SHA384,TLS13-SHA384-SHA384,TLS_SHA384_SHA384	SHA384_SHA384	-
0x0300C100	HIGH	HIGH	TLSv12	DH	GOST	Kuznyechik	256	Kuznyechik	9189	GOST2012-KUZNYECHIK-KUZNYECHIKOMAC,GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC	GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC	-
0x0300C101	HIGH	HIGH	TLSv12	DH	GOST	Magma	256	Magma	9189	GOST2012-MAGMA-MAGMAOMAC,GOSTR341112_256_WITH_MAGMA_CTR_OMAC,CTR-OMAC	GOSTR341112_256_WITH_MAGMA_CTR_OMAC	-
0x0300C102	HIGH	HIGH	TLSv12	DH	GOST	GOST89	256	GOST89	9189	GOST2012-GOST8912-IANA,GOSTR341112_256_WITH_28147_CNT_IMIT,CNT-IMIT,IANA-GOST2012-GOST8912-GOST8912,GOST2012-GOST8912-GOST8912	GOSTR341112_256_WITH_28147_CNT_IMIT	-
0x0300C103	HIGH	HIGH	TLSv13	DH	GOST	Kuznyechik	256	Kuznyechik	-?-	TLS13_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L	TLS13_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L	-
0x0300C104	HIGH	HIGH	TLSv13	DH	GOST	Magma	256	Magma	-?-	TLS13_GOSTR341112_256_WITH_MAGMA_MGM_L	TLS13_GOSTR341112_256_WITH_MAGMA_MGM_L	-
0x0300C105	HIGH	HIGH	TLSv13	DH	GOST	Kuznyechik	256	Magma	-?-	TLS13_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S	TLS13_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S	-
0x0300C106	HIGH	HIGH	TLSv13	DH	GOST	Magma	256	Magma	-?-	TLS13_GOSTR341112_256_WITH_MAGMA_MGM_S	TLS13_GOSTR341112_256_WITH_MAGMA_MGM_S	-
0x0300CC12	-?-	high	TLSv12	RSA	RSA	ChaCha20-Poly1305	256	AEAD	-?-	RSA-CHACHA20-POLY1305	RSA_WITH_CHACHA20_POLY1305	C
0x0300CC13	HIGH	HIGH	TLSv12	ECDH	RSA	ChaCha20-Poly1305	256	AEAD	-?-	ECDHE-RSA-CHACHA20-POLY1305-SHA256-OLD,ECDHE-RSA-CHACHA20-POLY1305-OLD	ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,ECDHE_RSA_CHACHA20_POLY1305	C
#0x0300CC13-old	HIGH	HIGH	TLSv12	ECDH	RSA	ChaCha20-Poly1305	256	AEAD	-	ECDHE-RSA-CHACHA20-POLY1305	ECDHE_RSA_WITH_CHACHA20_POLY1305	B
0x0300CC14	HIGH	HIGH	TLSv12	ECDH	ECDSA	ChaCha20-Poly1305	256	AEAD	-?-	ECDHE-ECDSA-CHACHA20-POLY1305-SHA256-OLD,ECDHE-ECDSA-CHACHA20-POLY1305-OLD	ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,ECDHE_ECDSA_CHACHA20_POLY1305	C
#0x0300CC14-old	HIGH	HIGH	TLSv12	ECDH	ECDSA	ChaCha20-Poly1305	256	AEAD	-	ECDHE-ECDSA-CHACHA20-POLY1305	ECDHE_ECDSA_WITH_CHACHA20_POLY1305	B
0x0300CC15	HIGH	HIGH	TLSv12	DH	RSA	ChaCha20-Poly1305	256	AEAD	-?-	DHE-RSA-CHACHA20-POLY1305-SHA256-OLD,DHE-RSA-CHACHA20-POLY1305-OLD	DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,DHE_RSA_CHACHA20_POLY1305	C
#0x0300CC15-old	HIGH	HIGH	TLSv12	DH	RSA	ChaCha20-Poly1305	256	AEAD	-	DHE-RSA-CHACHA20-POLY1305	DHE_RSA_WITH_CHACHA20_POLY1305	B
0x0300CC16	HIGH	HIGH	TLSv12	DH	PSK	ChaCha20-Poly1305	256	AEAD	-	DHE-PSK-CHACHA20-POLY1305	DHE_PSK_WITH_CHACHA20_POLY1305	B
0x0300CC17	HIGH	HIGH	TLSv12	PSK	PSK	ChaCha20-Poly1305	256	AEAD	-	PSK-CHACHA20-POLY1305	PSK_WITH_CHACHA20_POLY1305	B
0x0300CC18	HIGH	HIGH	TLSv12	ECDHEPSK	ECDHE	ChaCha20-Poly1305	256	AEAD	-	ECDHE-PSK-CHACHA20-POLY1305	ECDHE_PSK_WITH_CHACHA20_POLY1305	B
0x0300CC19	HIGH	HIGH	TLSv12	DH	RSA	ChaCha20-Poly1305	256	AEAD	-	RSA-PSK-CHACHA20-POLY1305	RSA_PSK_WITH_CHACHA20_POLY1305	B
0x0300CC20	HIGH	HIGH	TLSv12	RSA	RSA	ChaCha20	256	SHA1	-?-	RSA-CHACHA20-SHA	RSA_WITH_CHACHA20_SHA	C
0x0300CC21	HIGH	HIGH	TLSv12	ECDH	RSA	ChaCha20	256	SHA1	-?-	ECDHE-RSA-CHACHA20-SHA	ECDHE_RSA_WITH_CHACHA20_SHA	C
0x0300CC22	HIGH	HIGH	TLSv12	ECDH	RSA	ChaCha20	256	SHA1	-?-	ECDHE-ECDSA-CHACHA20-SHA	ECDHE_ECDSA_WITH_CHACHA20_SHA	C
0x0300CC23	HIGH	HIGH	TLSv12	DH	RSA	ChaCha20	256	SHA1	-?-	DHE-RSA-CHACHA20-SHA	DHE_RSA_WITH_CHACHA20_SHA	C
0x0300CC24	HIGH	HIGH	TLSv12	DH	PSK	ChaCha20	256	SHA1	-?-	DHE-PSK-CHACHA20-SHA	DHE_PSK_WITH_CHACHA20_SHA	C
0x0300CC25	HIGH	HIGH	TLSv12	PSK	PSK	ChaCha20	256	SHA1	-?-	PSK-CHACHA20-SHA	PSK_WITH_CHACHA20_SHA	C
0x0300CC26	HIGH	HIGH	TLSv12	ECDH	RSA	ChaCha20	256	SHA1	-?-	ECDHE-PSK-CHACHA20-SHA	ECDHE_PSK_WITH_CHACHA20_SHA	C
0x0300CC27	HIGH	HIGH	TLSv12	RSAPSK	RSA	ChaCha20	256	SHA1	-?-	RSA-PSK-CHACHA20-SHA	RSA_PSK_WITH_CHACHA20_SHA	C
0x0300CCA0	-?-	high	TLSv12	RSA	RSA	ChaCha20-Poly1305	256	AEAD	-?-	RSA-CHACHA20-POLY1305	RSA_WITH_CHACHA20_POLY1305	C
0x0300CCA1	HIGH	HIGH	TLSv12	ECDH	RSA	ChaCha20-Poly1305	256	AEAD	-?-	ECDHE-RSA-CHACHA20-POLY1305	ECDHE_RSA_WITH_CHACHA20_POLY1305	C
0x0300CCA2	HIGH	HIGH	TLSv12	ECDH	ECDSA	ChaCha20-Poly1305	256	AEAD	-?-	ECDHE-ECDSA-CHACHA20-POLY1305	ECDHE_ECDSA_WITH_CHACHA20_POLY1305	C
0x0300CCA3	HIGH	HIGH	TLSv12	DH	RSA	ChaCha20-Poly1305	256	AEAD	-?-	DHE-RSA-CHACHA20-POLY1305	DHE_RSA_WITH_CHACHA20_POLY1305	C
0x0300CCA4	HIGH	HIGH	TLSv12	DH	PSK	ChaCha20-Poly1305	256	AEAD	-?-	DHE-PSK-CHACHA20-POLY1305	DHE_PSK_WITH_CHACHA20_POLY1305	C
0x0300CCA5	HIGH	HIGH	TLSv12	PSK	PSK	ChaCha20-Poly1305	256	AEAD	-?-	PSK-CHACHA20-POLY1305	PSK_WITH_CHACHA20_POLY1305	C
0x0300CCA6	HIGH	HIGH	TLSv12	ECDHEPSK	ECDHE	ChaCha20-Poly1305	256	AEAD	-?-	ECDHE-PSK-CHACHA20-POLY1305	ECDHE_PSK_WITH_CHACHA20_POLY1305	C
0x0300CCA7	HIGH	HIGH	TLSv12	DH	RSA	ChaCha20-Poly1305	256	AEAD	-?-	RSA-PSK-CHACHA20-POLY1305	RSA_PSK_WITH_CHACHA20_POLY1305	C
0x0300CCA8	HIGH	HIGH	TLSv12	ECDH	RSA	ChaCha20-Poly1305	256	AEAD	7905	ECDHE-RSA-CHACHA20-POLY1305-SHA256	ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256	C
0x0300CCA9	HIGH	HIGH	TLSv12	ECDH	ECDSA	ChaCha20-Poly1305	256	AEAD	7905	ECDHE-ECDSA-CHACHA20-POLY1305-SHA256	ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256	C
0x0300CCAA	HIGH	HIGH	TLSv12	DH	RSA	ChaCha20-Poly1305	256	AEAD	7905	DHE-RSA-CHACHA20-POLY1305-SHA256	DHE_RSA_WITH_CHACHA20_POLY1305_SHA256	C
0x0300CCAB	HIGH	HIGH	TLSv12	PSK	PSK	ChaCha20-Poly1305	256	AEAD	7905	PSK-CHACHA20-POLY1305-SHA256	PSK_WITH_CHACHA20_POLY1305_SHA256	C
0x0300CCAC	HIGH	HIGH	TLSv12	ECDHEPSK	ECDHE	ChaCha20-Poly1305	256	AEAD	7905	ECDHE-PSK-CHACHA20-POLY1305-SHA256	ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256	C
0x0300CCAD	HIGH	HIGH	TLSv12	DHEPSK	DHE	ChaCha20-Poly1305	256	AEAD	7905	DHE-PSK-CHACHA20-POLY1305-SHA256	DHE_PSK_WITH_CHACHA20_POLY1305_SHA256	C
0x0300CCAE	HIGH	HIGH	TLSv12	RSAPSK	RSA	ChaCha20-Poly1305	256	AEAD	7905	RSA-PSK-CHACHA20-POLY1305-SHA256	RSA_PSK_WITH_CHACHA20_POLY1305_SHA256	C
0x0300D001	-?-	high	TLSv12	ECDH	PSK	AESGCM	128	AEAD	8442	ECDHE-PSK-AES128-GCM-SHA256	ECDHE_PSK_WITH_AES_128_GCM_SHA256	R
0x0300D002	-?-	high	TLSv12	ECDH	PSK	AESGCM	256	AEAD	8442	ECDHE-PSK-AES256-GCM-SHA384	ECDHE_PSK_WITH_AES_256_GCM_SHA384	R
0x0300D003	-?-	high	TLSv12	ECDH	PSK	AESCCM8	128	AEAD	8442	ECDHE-PSK-AES128-CCM8-SHA256	ECDHE_PSK_WITH_AES_128_CCM_8_SHA256	R
0x0300D005	-?-	high	TLSv12	ECDH	PSK	AESCCM	128	AEAD	8442	ECDHE-PSK-AES128-CCM-SHA256	ECDHE_PSK_WITH_AES_128_CCM_SHA256	R
0x0300FEE0	-?-	weak	SSLv3	RSA_FIPS	RSA_FIPS	3DES	112	SHA1	-?-	RSA-FIPS-3DES-EDE-SHA-2	RSA_FIPS_WITH_3DES_EDE_CBC_SHA_2	M
0x0300FEE1	-?-	weak	SSLv3	RSA_FIPS	RSA_FIPS	DES	56	SHA1	-?-	RSA-FIPS-DES-CBC-SHA-2	RSA_FIPS_WITH_DES_CBC_SHA_2	M
0x0300FEFE	-?-	weak	SSLv3	RSA_FIPS	RSA_FIPS	DES	56	SHA1	-?-	RSA-FIPS-DES-CBC-SHA	RSA_FIPS_WITH_DES_CBC_SHA	N
0x0300FEFF	-?-	weak	SSLv3	RSA_FIPS	RSA_FIPS	3DES	112	SHA1	-?-	RSA-FIPS-3DES-EDE-SHA	RSA_FIPS_WITH_3DES_EDE_CBC_SHA	N
0x0300FF00	HIGH	weak	SSLv3	RSA	RSA	GOST89	256	MD5	5830	GOST-MD5	GOSTR341094_RSA_WITH_28147_CNT_MD5	G
0x0300FF01	HIGH	HIGH	SSLv3	RSA	RSA	GOST89	256	GOST94	5830	GOST-GOST94	RSA_WITH_28147_CNT_GOST94	G
0x0300FF02	HIGH	HIGH	SSLv3	RSA	RSA	GOST89	256	GOST89	-?-	GOST-GOST89MAC	GOST-GOST89MAC	G
0x0300FF03	HIGH	HIGH	SSLv3	RSA	RSA	GOST89	256	GOST89	-?-	GOST-GOST89STREAM	GOST-GOST89STREAM	G
0x0300FF85	HIGH	HIGH	TLSv13	GOST	GOST	GOST89	256	GOST89	-?-	LEGACY-GOST2012-GOST8912-GOST8912,GOST2012-GOST8912-GOST891	GOSTR341112_256_WITH_28147_CNT_IMIT	FIXME
0x0300FF87	-?-	weak	TLSv13	GOST	GOST	None	0	GOST89	-?-	GOST2012-NULL-GOST12	GOSTR341112_256_WITH_NULL_GOSTR3411	FIXME
#--------------+-------+-------+-------+-------+-------+-------+-------+-------+-------+---------------+-------+---------------+
# hex const	openssl	sec	ssl	keyx	auth	enc	bits	mac	rfc	cipher,aliases	const	comment

__END__

# comments from above table (still TODO)
# B
# BSAFE	seen in BSAFE sources
# C
# G
# H
# I
# K
# L
# M	definition unknown:  0x001E, "KRB5_WITH_DES_CBC_SHA"
# M	OpenSSL 3.5 defines: 0x001E, "SSL_FORTEZZA_KEA_WITH_RC4_128_SHA"
#	since 4/2025 SSL_FORTEZZA_KEA_WITH_RC4_128_SHA will be used (because defined in OpenSSL's t1_trce.c)
# N
# O
# P
# PCT	different protocol PCT
# PGP
# Q
# R

## CIPHERS }

