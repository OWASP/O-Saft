#!/usr/bin/perl
## PACKAGE {

#!# Copyright (c) 2022, Achim Hoffmann
#!# This  software is licensed under GPLv2. Please see o-saft.pl for details.

package main;   # ensure that main:: variables are used

## no critic qw(Documentation::RequirePodSections)
# SEE Perl:perlcritic

use strict;
use warnings;

no warnings 'redefine'; ## no critic qw(TestingAndDebugging::ProhibitNoWarnings)
   # must be herein, as most subroutines are already defined in main
   # warnings pragma is local to this file!

BEGIN { # mainly required for testing ...
    # SEE Perl:BEGIN perlcritic
    my $_path = $0;     $_path =~ s#[/\\][^/\\]*$##x;
    unshift(@INC, $_path)   if (1 > (grep{/^$_path$/} @INC));
    unshift(@INC, "..")     if (1 > (grep{/^\.\.$/}   @INC));
    unshift(@INC, ".")      if (1 > (grep{/^\.$/}     @INC));
}

use OSaft::Text qw(%STR print_pod);
use osaft;

my  $SID_usr    = "@(#) o-saft-usr.pm 2.6 22/10/31 20:24:01";


#_____________________________________________________________________________
#_____________________________________________________ public documentation __|

=pod

=encoding utf8


=head1 NAME

o-saft-usr.pm - module for o-saft.pl's user definable functions

=head1 SYNOPSIS

=over 2

=item require q{o-saft-usr.pm};     # in perl code

=item o-saft-usr.pm --help          # on command-line will print help

=back


=head1 DESCRIPTION

Defines all functions for user customisation.

WARNING: this is not a perl module defined with `package', but uses:
    package main;
hence is is recommended that all variables and function use a unique
prefix like:
    usr_  or _usr_

=head2 Functions defined herein

=over 4

=item usr_pre_init( )

At beginning, right before initialising internal data.

=item usr_pre_file( )

At beginning, right after initialising internal data.

=item usr_pre_args( )

Right before reading command-line arguments.  All internal structures
and variables are initialised, all external files are read (except
configuration files specified witj  I<--cfg_*=>  option.

=item usr_pre_exec( )

All command-line arguments are read. Right before executing myself.

=item usr_pre_cipher( )

Before getting list of ciphers.

=item usr_pre_main( )

Before executing commands.

=item usr_pre_host( )

Before starting loop over all given hosts.

=item usr_pre_info( )

DNS stuff and SNI connection checked. Before doing commands per host.

=item usr_pre_open( )

Before opening connection.

=item usr_pre_cmds( )

Before listing or checking anything.  SSL connection  is open and all
data available in  $Net::SSLinfo::* .

=item usr_pre_data( )

All data according SSL connection and ciphers available in %data  and
@results. Before doing any checks and before printing anything.

=item usr_pre_print( )

All checks are done, ready to print data from %checks also.

=item usr_pre_next( )

Host completely processed. Right before next host.

=item usr_pre_exit( )

Right before program exit.

=item usr_version()

Return version of this interface.

=back

=head2 Variables which may be used herein

They must be defined as `our' in L<o-saft.pl|o-saft.pl>:

=over 4

=item $VERSION

=item %data

=item %cfg, i.e. trace, traceARG, traceCMD, traceKEY, verbose

=item %checks

=item %org

=back

Functions being used in L<o-saft.pl|o-saft.pl> shoudl be defined as empty stub there.
For example:

    sub usr_pre_args() {}

=cut

#_____________________________________________________________________________
#__________________________________________________________________ methods __|

sub _usr_dbx { my @args = @_; _trace(join(" ", @args, "\n")); return; } # requires --v

# user functions
# -------------------------------------
# These functions are called in o-saft.pl

sub usr_version     { return "16.09.16"; }  # changed only if fucntionality changed!

sub usr_pre_init    {
    _usr_dbx("usr_pre_init ...");
    return;
};

sub usr_pre_file    {
    _usr_dbx("usr_pre_file ...");
    return;
};

sub usr_pre_args    {
    _usr_dbx("usr_pre_args ...");
    return;
};

sub usr_pre_exec    {
    _usr_dbx("usr_pre_exec ...");
    # All arguments and options are parsed.
    # Unknown commands are not available with _is_do() but can be
    # searched for in cfg{'done'}->{'arg_cmds'} which allows users
    # to "create" and use their own commands without changing 
    # o-saft.pl itself. However, o-saft.pl will print a WARNING then.
    return;
};

sub usr_pre_cipher  {
    _usr_dbx("usr_pre_cipher ...");
    return;
};

sub usr_pre_main    {
    _usr_dbx("usr_pre_main ...");
    return;
};

sub usr_pre_host    {
    _usr_dbx("usr_pre_host ...");
    return;
};

sub usr_pre_info    {
    _usr_dbx("usr_pre_info ...");
    return;
};

sub usr_pre_open    {
    _usr_dbx("usr_pre_open ...");
    ###
    ### sample code for using your own socket
    ###
    #use IO::Socket;
    #$Net::SSLinfo::socket = IO::Socket::INET->new(PeerHost=>'localhost', PeerPort=>443, Proto=>'tcp') 
    #or die "**ERROR usr_pre_open socket(): $!\n";
    return;
};

sub usr_pre_cmds    {
    _usr_dbx("usr_pre_cmds ...");
    return;
};

sub usr_pre_data    {
    _usr_dbx("usr_pre_data ...");
    return;
};

sub usr_pre_print   {
    _usr_dbx("usr_pre_print ...");
    return;
};

sub usr_pre_next    {
    _usr_dbx("usr_pre_next ...");
    return;
};

sub usr_pre_exit    {
    _usr_dbx("usr_pre_exit ...");
    return;
};

sub _main_usr       {
    my $arg = shift || "--help";    # without argument print own help
    ## no critic qw(InputOutput::RequireEncodingWithUTF8Layer)
    #   see t/.perlcriticrc for detailed description of "no critic"
    #  SEE Perl:binmode()
    binmode(STDOUT, ":unix:utf8");
    binmode(STDERR, ":unix:utf8");
    print_pod($0, __FILE__, $SID_usr)   if ($arg =~ m/--?h(elp)?$/x);
    # no other options implemented yet
    print "$SID_usr\n"      if ($arg =~ /^version$/);
   #print "$VERSION\n"      if ($arg =~ /^[-+]?V(ERSION)?$/);
    exit 0;
} # _main

sub usr_done        {}; # dummy to check successful include

=pod

=head1 VERSION

2.6 2022/10/31

=head1 AUTHOR

13-nov-13 Achim Hoffmann

=cut

## PACKAGE }

# local functions {
# -------------------------------------
# local functions }

#_____________________________________________________________________________
#_____________________________________________________________________ self __|

_main_usr(@ARGV) if (not defined caller);

1;
