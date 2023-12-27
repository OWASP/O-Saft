#!/usr/bin/perl
## PACKAGE {

#!# Copyright (c) 2023, Achim Hoffmann
#!# This  software is licensed under GPLv2. Please see o-saft.pl for details.

package OSaft::Text;

use strict;
use warnings;

my  $SID_text   =  "@(#) Text.pm 1.10 23/12/27 11:41:04";
our $VERSION    =  "23.11.23";

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
use base     qw(Exporter);
our @EXPORT_OK  = qw( %STR print_pod text_done );

# SEE Perl:constant

#_____________________________________________________________________________
#_____________________________________________________ public documentation __|

=pod

=encoding utf8

=head1 NAME

OSaft::Text -- common texts for O-Saft and related tools


=head1 SYNOPSIS

=over 2

=item use OSaft::Text;          # in perl code

=item OSaft/Text.pm --help      # on command-line will print help

=back


=head1 OPTIONS

=over 4

=item --help

=back


=head1 DESCRIPTION

Utility package for O-Saft (o-saft.pl and related tools).  It declares and
defines common  L</TEXTS>  to be used in the calling tool.
All variables and methods are defined in the  OSaft::Text  namespace.


=head1 TEXTS

Perlish spoken, all texts are L</VARIABLES>.

=head1 VARIABLES

=head3 %STR{ERROR}

=head3 %STR{WARN}

=head3 %STR{HINT}

=head3 %STR{USAGE}

=head3 %STR{DBX}

=head3 %STR{UNDEF}

=head3 %STR{NOTXT}

=head3 %STR{MAKEVAL}


=head1 METHODS

=head3 OSaft::Text::print_pod($file)

Print POD for specified file, exits program.


=head1 SEE ALSO

# ...


=head1 VERSION

1.10 2023/12/27


=head1 AUTHOR

22-feb-22 Achim Hoffmann

=cut

#_____________________________________________________________________________
#_________________________________________________________ internal methods __|

# SEE Perl:Undefined subroutine
*_warn    = sub { print(join(" ", "**WARNING:", @_), "\n"); return; } if not defined &_warn;
*_dbx     = sub { print(join(" ", "#dbx#"     , @_), "\n"); return; } if not defined &_dbx;

#_____________________________________________________________________________
#__________________________________________________________________ methods __|

sub print_pod       {
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

#_____________________________________________________________________________
#_____________________________________________________________________ main __|


sub _main_text      {
    my @argv = @_;
    push(@argv, "--help") if (0 > $#argv);
    binmode(STDOUT, ":unix:utf8"); ## no critic qw(InputOutput::RequireEncodingWithUTF8Layer)
    binmode(STDERR, ":unix:utf8"); ## no critic qw(InputOutput::RequireEncodingWithUTF8Layer)
    # got arguments, do something special
    while (my $arg = shift @argv) {
        print_pod($0, __PACKAGE__, $SID_text)   if ($arg =~ m/^--?h(?:elp)?$/x);# print own help
        if ($arg =~ m/^--(?:test[_.-]?)text/x) {
            $arg = "--test-text";
            printf("#$0: direct testing not yet possible, please try:\n   o-saft.pl $arg\n");
        }
    }
    exit 0;
} # _main_text

sub text_done  {};      # dummy to check successful include

## PACKAGE }

#_____________________________________________________________________________
#_____________________________________________________________________ self __|

_main_text(@ARGV) if (not defined caller);

1;

