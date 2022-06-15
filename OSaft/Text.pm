#!/usr/bin/perl

## PACKAGE {

#!# Copyright (c) 2022, Achim Hoffmann
#!# This  software is licensed under GPLv2. Please see o-saft.pl for details.

package OSaft::Text;

use strict;
use warnings;
use utf8;

my  $SID_text   =  "@(#) Text.pm 1.2 22/06/15 10:49:45";
our $VERSION    =  "22.05.22";

#_____________________________________________________________________________
#________________________________________________________________ variables __|

our %STR = (
    'ERROR'     => "**ERROR:",
    'WARN'      => "**WARNING:",
    'HINT'      => "!!Hint:",
    'USAGE'     => "**USAGE:",
    'DBX'       => "#dbx#",
    'UNDEF'     => "<<undef>>",
    'NOTXT'     => "<<>>",
    'MAKEVAL'   => "<<value not printed (OSAFT_MAKE exists)>>",
);

# FIXME: perlcritic complains to not declare (global) package variables, but
#        the purpose of this module is to do that. This may change in future.

use Exporter qw(import);
#use base qw(Exporter);
our @ISA        = qw(Exporter);
our @EXPORT_OK  = qw( %STR print_pod );

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

Perlish spoken, all texts are variables:

=over 4

=item %STR{ERROR}

=item %STR{WARN}

=item %STR{HINT}

=item %STR{USAGE}

=item %STR{DBX}

=item %STR{UNDEF}

=item %STR{NOTXT}

=item %STR{MAKEVAL}

=back


=head1 METHODS

=head2 OSaft::Text::print_pod($file)

Print POD for specified file, exits program.

=cut


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
#_________________________________________________________ internal methods __|


sub _main_text      {
    my @argv = @_;
    push(@argv, "--help") if (0 > $#argv);
    binmode(STDOUT, ":unix:utf8");
    binmode(STDERR, ":unix:utf8");
    # got arguments, do something special
    while (my $arg = shift @argv) {
        print_pod($0, __PACKAGE__, $SID_text)   if ($arg =~ m/^--?h(?:elp)?$/); # print own help
        if ($arg =~ m/^--(?:test[_.-]?)text/) {
            $arg = "--test-text";
            printf("#$0: direct testing not yet possible, please try:\n   o-saft.pl $arg\n");
        }
    }
    exit 0;
} # _main_text

sub text_done  {};      # dummy to check successful include

## PACKAGE }

#_____________________________________________________________________________
#_____________________________________________________ public documentation __|

=pod

=head1 SEE ALSO

# ...

=head1 VERSION

1.2 10:49:45

=head1 AUTHOR

22-feb-22 Achim Hoffmann

=cut

#_____________________________________________________________________________
#_____________________________________________________________________ self __|

# SEE Perl:Undefined subroutine
*_warn = sub { print(join(" ", "**WARNING:", @_), "\n"); return; } if not defined &_warn;
*_dbx  = sub { print(join(" ", "#dbx#"     , @_), "\n"); return; } if not defined &_dbx;
# TODO: return if (grep{/(?:--no.?warn)/} @ARGV);   # ugly hack

_main_text(@ARGV) if (not defined caller);

1;

