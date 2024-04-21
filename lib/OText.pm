#!/usr/bin/perl
## PACKAGE {

#!# Copyright (c) 2024, Achim Hoffmann
#!# This  software is licensed under GPLv2. Please see o-saft.pl for details.

package OText;

use strict;
use warnings;

my  $SID_otext  =  "@(#) OText.pm 3.12 24/04/21 18:38:24";
our $VERSION    =  "24.01.24";

#_____________________________________________________________________________
#________________________________________________ public (export) variables __|

our %STR = (
    'ERROR'     => "**ERROR: ",
    'WARN'      => "**WARNING: ",
    'HINT'      => "!!Hint: ",
    'INFO'      => "**INFO: ",
    'USAGE'     => "**USAGE: ",
    'DBX'       => "#dbx# ",
    'UNDEF'     => "<<undef>>",
    'NOTXT'     => "<<>>",
    'MAKEVAL'   => "<<value not printed (OSAFT_MAKE exists)>>",
);

use Exporter qw(import);
BEGIN { our @EXPORT_OK  = qw( %STR );
   # print_pod done must be used full qualified
}

#_____________________________________________________________________________
#_____________________________________________________ public documentation __|

=pod

=encoding utf8


=head1 NAME

OText - Perl module providing texts for O-Saft and related tools


=head1 SYNOPSIS

=over 2

=item use OText;        # in perl code

=item OText.pm --help   # on command-line will print help

=back


=head1 OPTIONS

=over 4

=item --help

=back


=head1 DESCRIPTION

Utility package for O-Saft (o-saft.pl and related tools).  It declares and
defines common  L</TEXTS>  to be used in the calling tool.
All variables and methods are defined in the  OText  namespace.


=head1 TEXTS

Perlish spoken, all texts are L</VARIABLES>.

=head1 VARIABLES

=head3 %STR{ERROR}

=head3 %STR{WARN}

=head3 %STR{HINT}

=head3 %STR{INFO}

=head3 %STR{USAGE}

=head3 %STR{DBX}

=head3 %STR{UNDEF}

=head3 %STR{NOTXT}

=head3 %STR{MAKEVAL}


=head1 METHODS

=head2 Functions for internal testing; initiated with option  I<--test-*>

=head3 test_show( )

Print text constants defined herein.

=head3 print_pod($file)

Print POD for specified file, exits program.


=head1 SEE ALSO

# ...


=head1 VERSION

3.12 2024/04/21


=head1 AUTHOR

22-feb-22 Achim Hoffmann

=cut

#_____________________________________________________________________________
#__________________________________________________________________ methods __|

sub print_pod   {
    #? print POD of specified file; exits program
    my $file = shift;   # filename where to read POD from
    my $pack = shift;   # package name
    my $vers = shift;   # package version
    printf("# %s %s\n", $pack, $vers);
    if (eval {require Pod::Perldoc;}) {
        # pod2usage( -verbose => 1 );
        exit( Pod::Perldoc->run(args=>[$file]) );
    }
    if (qx(perldoc -V)) {   ## no critic qw(InputOutput::ProhibitBacktickOperators)
            # may return:  You need to install the perl-doc package to use this program.
            #exec "perldoc $0"; # scary ...
        printf("# no Pod::Perldoc installed, please try:\n  perldoc $file\n");
    }
    exit 0;
} # print_pod

#_____________________________________________________________________________
#____________________________________________________ internal test methods __|

sub test_show   {
    #? dispatcher for internal tests, initiated with option --test-*
    my $arg = shift;    # normalised option, like --testinit, --testcipherlist
    printf("#%s:\n", (caller(0))[3]);
    print <<'EoT';

=== internal text constants ===
=
= variable      value
=--------------+-------------------
EoT

    printf(" STR{'%s'}\t%s\n", $_, $STR{$_}) foreach (sort keys(%STR));
    printf("=--------------+-------------------\n");
    return;
} # test

#_____________________________________________________________________________
#_____________________________________________________________________ main __|

sub _main   {
    my @argv = @_;
    push(@argv, "--help") if (0 > $#argv);
    # SEE Perl:binmode()
    binmode(STDOUT, ":unix:utf8"); ## no critic qw(InputOutput::RequireEncodingWithUTF8Layer)
    binmode(STDERR, ":unix:utf8"); ## no critic qw(InputOutput::RequireEncodingWithUTF8Layer)
    # got arguments, do something special
    while (my $arg = shift @argv) {
        if ($arg =~ m/^--?h(?:elp)?$/msx)       { print_pod($0, __PACKAGE__, $SID_otext); } # print own help
        if ($arg =~ /^version$/x)               { print "$SID_otext\n"; next; }
        if ($arg =~ /^[-+]?V(ERSION)?$/x)       { print "$VERSION\n";   next; }
        if ($arg =~ m/^--(?:test[_.-]?)text/mx) { test_show($arg); }
    }
    exit 0;
} # _main

sub done    {}; # dummy to check successful include

## PACKAGE }

#_____________________________________________________________________________
#_____________________________________________________________________ self __|

_main(@ARGV) if (not defined caller);

1;

