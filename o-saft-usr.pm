#!/usr/bin/perl -w

=pod

=head1 NAME

o-saft-usr.pm - module for o-saft.pl's user definable functions

=head1 SYNOPSIS

require "o-saft-usr.pm";

=head1 DESCRIPTION

Defines all function for user customization.

=head2 Functions defined herein

=over 4

=item usr_pre_file( )

At beginning, right before reading any  L<RC-FILE> or  L<DEBUG-FILE>

=item usr_pre_args( )

Right before reading command line arguments.  All internal structures
and variables are initialized, all external files are read (except
configuration files specified witj  I<--cfg_*=>  option.

=item usr_pre_exec( )

All command line arguments are read. Right before executing myself.

=item usr_pre_main( )

Before executing commands.

=item usr_pre_host( )

Before starting loop over all given hosts.

=item usr_pre_cipher( )

DNS stuff and SNI connection checked. Before getting list of ciphers.

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

=back

=head2 Variables which may be used herein

They must be defined as `our' in L<o-saft.pl>:

=over 4

=item $VERSION

=item $me   $mename   $mepath

=item %data

=item %cfg, i.e. trace, traceARG, traceCMD, traceKEY, verbose

=item %checks

=item %org

=back

Functions being used in L<o-saft.pl> shoudl be defined as empty stub there.
For example:

    sub usr_pre_args() {}

=cut

my  $SID    = "@(#) o-saft-usr.pm 1.1 13/12/29 14:20:45";

no warnings 'redefine';
   # must be herein, as most subroutines are already defined in main
   # warnings pragma is local to this file!
package main;   # ensure that main:: variables are used

sub _dbx { _trace(join(" ", @_)); } # requires --v

# user functions
# -------------------------------------
sub usr_pre_file()  {
    _dbx("usr_pre_file ...");
};

sub usr_pre_args()  {
    _dbx("usr_pre_args ...");
};

sub usr_pre_exec()  {
    _dbx("usr_pre_exec ...");
};

sub usr_pre_main()  {
    _dbx("usr_pre_main ...");
};

sub usr_pre_host()  {
    _dbx("usr_pre_host ...");
};

sub usr_pre_cipher() {
    _dbx("usr_pre_cipher ...");
};

sub usr_pre_cmds()  {
    _dbx("usr_pre_cmds ...");
};

sub usr_pre_data()  {
    _dbx("usr_pre_data ...");
};

sub usr_pre_print() {
    _dbx("usr_pre_print ...");
};

sub usr_pre_next()  {
    _dbx("usr_pre_next ...");
};

sub usr_pre_exit()  {
    _dbx("usr_pre_exit ...");
};

1;
