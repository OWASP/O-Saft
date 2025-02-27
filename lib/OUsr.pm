#!/usr/bin/perl -CADSio
## PACKAGE {

#!# Copyright (c) 2025, Achim Hoffmann
#!# This  software is licensed under GPLv2. Please see o-saft.pl for details.

package OUsr;
use strict;
use warnings;
use utf8;

# for description of "no critic" pragmas, please see  t/.perlcriticrc  and
# SEE Perl:perlcritic

## no critic qw(RegularExpressions::RequireExtendedFormatting)

#_____________________________________________________________________________
#___________________________________________________ package initialisation __|

my  $SID_ousr       = "@(#) OUsr.pm 3.19 25/01/10 17:14:04";
our $VERSION        = "24.06.24";   # changed only if fucntionality changed!


no warnings 'redefine'; ## no critic qw(TestingAndDebugging::ProhibitNoWarnings)
   # must be herein, as most subroutines are already defined in main
   # warnings pragma is local to this file!

# public package variables
{
## no critic qw(Variables::ProhibitPackageVars)
our $trace          = 0;
our $verbose        = 0;
our $prefix_trace   = "#". __PACKAGE__ . ":";
our $prefix_verbose = "#". __PACKAGE__ . ":";
}

use Exporter    qw(import);

BEGIN { # mainly required for testing ...
    # SEE Perl:@INC
    # SEE Perl:BEGIN perlcritic
    my $_path = $0;     $_path =~ s#[/\\][^/\\]*$##x;
    if (exists $ENV{'PWD'} and not (grep{/^$ENV{'PWD'}$/} @INC) ) {
        unshift(@INC, $ENV{'PWD'});
    }
    unshift(@INC, $_path)   if not (grep{/^$_path$/} @INC);
    unshift(@INC, "lib")    if not (grep{/^lib$/}    @INC);
    unshift(@INC, ".")      if not (grep{/^\.$/}     @INC);
    our @EXPORT_OK = qw(
        pre_init
        pre_file
        pre_args
        pre_exec
        pre_cipher
        pre_main
        pre_host
        pre_info
        pre_open
        pre_cmds
        pre_data
        pre_print
        pre_next
        pre_exit
        version
    );
}

use OText       qw(%STR);
use OCfg;

if (exists $INC{'lib/OTrace.pm'}) {
    *trace      = \&OTrace::trace;
} else {
    sub trace   {
        my @txt = @_;
        return if not return (grep{/--(?:trace(?:=\d*)?$)/}   @ARGV);
        printf("#%s: %s\n", __PACKAGE__, "@txt");
        return;
    };
}

#_____________________________________________________________________________
#_____________________________________________________ public documentation __|

=pod

=encoding utf8


=head1 NAME

OUsr.pm - Perl module for O-Saft user definable functions

=head1 SYNOPSIS

=over 2

=item use q{OUsr.pm};       # in perl code

=item require q{OUsr.pm};   # in perl code

=item OUsr.pm --help        # on command-line will print help

=back


=head1 DESCRIPTION

Defines all functions for user customisation.

=head2 METHODS

Hint: if functions are not used in the calling program, they should be defined
as empty stub there, for example:

    sub pre_args() {}

=head3 OUsr::pre_init( )

At beginning, right before initialising internal data.

=head3 OUsr::pre_file( )

At beginning, right after initialising internal data.

=head3 OUsr::pre_args( )

Right before reading command-line arguments.  All internal structures
and variables are initialised, all external files are read (except
configuration files specified witj  I<--cfg_*=>  option.

=head3 OUsr::pre_exec( )

All command-line arguments are read. Right before executing myself.

=head3 OUsr::pre_cipher( )

Before getting list of ciphers.

=head3 OUsr::pre_main( )

Before executing commands.

=head3 OUsr::pre_host( )

Before starting loop over all given hosts.

=head3 OUsr::pre_info( )

DNS stuff and SNI connection checked. Before doing commands per host.

=head3 OUsr::pre_open( )

Before opening connection.

=head3 OUsr::pre_cmds( )

Before listing or checking anything.  SSL connection  is open and all
data available in  $Net::SSLinfo::* .

=head3 OUsr::pre_data( )

All data according SSL connection and ciphers available in %data  and
@results. Before doing any checks and before printing anything.

=head3 OUsr::pre_print( )

All checks are done, ready to print data from %checks also.

=head3 OUsr::pre_next( )

Host completely processed. Right before next host.

=head3 OUsr::pre_exit( )

Right before program exit.

=head3 OUsr::version()

Return version of this interface.

=head2 VARAIBLES

Variables which may be used herein must be defined as `our' in  L<o-saft.pl|o-saft.pl>:

=head3 $VERSION

=head3 %data

=head3 %cfg, i.e. trace, traceARG, traceCMD, traceKEY, verbose

=head3 %checks

=head3 %org

=cut

#_____________________________________________________________________________
#__________________________________________________________________ methods __|

sub version     { return $VERSION; }

sub pre_init    {
    trace("pre_init ...");
    return;
};

sub pre_file    {
    trace("pre_file ...");
    return;
};

sub pre_args    {
    trace("pre_args ...");
    return;
};

sub pre_exec    {
    trace("pre_exec ...");
    # All arguments and options are parsed.
    # Unknown commands are not available with _is_do() but can be
    # searched for in cfg{'done'}->{'arg_cmds'} which allows users
    # to "create" and use their own commands without changing 
    # o-saft.pl itself. However, o-saft.pl will print a WARNING then.
    return;
};

sub pre_cipher  {
    trace("pre_cipher ...");
    return;
};

sub pre_main    {
    trace("pre_main ...");
    return;
};

sub pre_host    {
    trace("pre_host ...");
    return;
};

sub pre_info    {
    trace("pre_info ...");
    return;
};

sub pre_open    {
    trace("pre_open ...");
    ###
    ### sample code for using your own socket
    ###
    #use IO::Socket;
    #$Net::SSLinfo::socket = IO::Socket::INET->new(PeerHost=>'localhost', PeerPort=>443, Proto=>'tcp') 
    #or die "**ERROR pre_open socket(): $!\n";
    return;
};

sub pre_cmds    {
    trace("pre_cmds ...");
    return;
};

sub pre_data    {
    trace("pre_data ...");
    return;
};

sub pre_print   {
    trace("pre_print ...");
    return;
};

sub pre_next    {
    trace("pre_next ...");
    return;
};

sub pre_exit    {
    trace("pre_exit ...");
    return;
};

sub _main       {
    my $arg = shift || "--help";    # without argument print own help
    OText::print_pod($0, __FILE__, $SID_ousr) if ($arg =~ m/--?h(elp)?$/x);
    # no other options implemented yet
    print "$SID_ousr\n"     if ($arg =~ /^version$/);
    print "$VERSION\n"      if ($arg =~ /^[-+,]?V(ERSION)?$/);
    exit 0;
} # _main

sub done    {}; # dummy to check successful include

#_____________________________________________________________________________
#_____________________________________________________ public documentation __|

=pod

=head1 VERSION

3.19 2025/01/10

=head1 AUTHOR

13-nov-13 Achim Hoffmann

=cut

## PACKAGE }

#_____________________________________________________________________________
#_____________________________________________________________________ self __|

_main(@ARGV) if (not defined caller);

1;
