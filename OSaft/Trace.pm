#!/usr/bin/perl
## PACKAGE {

#!# Copyright (c) 2024, Achim Hoffmann
#!# This  software is licensed under GPLv2. Please see o-saft.pl for details.

package OSaft::Trace;

# HACKER's INFO
#       Following (internal) functions from o-saft.pl are used:
#       _is_cfg_intern()
#       _is_member()

## no critic qw(Subroutines::RequireArgUnpacking)
#        Parameters are ok for trace output.

## no critic qw(RegularExpressions::RequireExtendedFormatting)
#        We believe that most RegEx are not too complex.

# for Severity 2 only:
## no critic qw(ValuesAndExpressions::ProhibitMagicNumbers)
#        We have some constants herein, that's ok.

## no critic qw(ValuesAndExpressions::ProhibitNoisyQuotes)
#        We have a lot of single character strings, herein, that's ok.

## no critic qw(Variables::ProhibitPackageVars)

## no critic qw(TestingAndDebugging::RequireUseStrict)
#  `use strict;' not useful here, as we mainly use our global variables
use warnings;
# use strict;

no warnings 'redefine'; ## no critic qw(TestingAndDebugging::ProhibitNoWarnings)
   # must be herein, as most subroutines are already defined in main
   # warnings pragma is local to this file!
no warnings 'once';     ## no critic qw(TestingAndDebugging::ProhibitNoWarnings)
   # "... used only once: possible typo ..." appears when called as main only

my  $SID_trace      = "@(#) Trace.pm 2.3 24/01/08 11:42:36";
our $VERSION        = "24.01.24";

#_____________________________________________________________________________
#___________________________________________________ package initialisation __|

# public package variables
our $trace          = 0;
our $verbose        = 0;
our $prefix_trace   = "#". __PACKAGE__ . ":";
our $prefix_verbose = "#". __PACKAGE__ . ":";

BEGIN { # mainly required for testing ...
    # SEE Perl:@INC
    # SEE Perl:BEGIN perlcritic
    my $_me   = $0;     $_me   =~ s#.*[/\\]##x;
    my $_path = $0;     $_path =~ s#[/\\][^/\\]*$##x;
    unshift(@INC, $_path)   if (1 > (grep{/^$_path$/} @INC));
    unshift(@INC, "..")     if (1 > (grep{/^\.\.$/}   @INC));
    unshift(@INC, ".")      if (1 > (grep{/^\.$/}     @INC));
    if (not exists &_is_cfg_intern) {
        sub _is_member      { my ($is,$ref)=@_; return grep({lc($is) eq lc($_)} @{$ref}); }
        sub _is_cfg_intern  { return _is_member(shift, \@{$cfg{'commands_int'}});}
    }
}

use Exporter qw(import);
use base     qw(Exporter);
our @EXPORT_OK  = qw(
    trace_
    trace
    trace0
    trace1
    trace2
    trace3
    trace_arg
    trace_cmd
    trace_args
    trace_init
    trace_exit
    trace_test
    trace_time
    trace_ciphers_list
    trace_ciphers_list
    trace_targets
    trace_done
);

# NOTE: following probably needed for ancient Perl 4.x, 5.0x
#our $HAVE_XS = eval {
#    local $SIG{'__DIE__'} = 'DEFAULT';
#    eval {
#        require XSLoader;
#        XSLoader::load(__PACKAGE__, $VERSION);
#        1;
#    } or do {
#        require DynaLoader;
#        bootstrap OSaft::Trace $VERSION;
#        1;
#    };
#} ? 1 : 0;

#-------------------------------------------------------------------------
# Version < 24.01.24
#o-saft.pl::Net::SSLeay
#Net::SSLinfo::do_ssl_open(localhost,443,,) {
#Net::SSLinfo::do_ssl_open cipherlist: ALL:NULL:eNULL:aNULL:LOW:EXP
#Net::SSLinfo::do_ssl_open ::use_http: 1		<== inkonsistent
#Net::SSLinfo::do_ssl_open: request localhost:443	<== inkonsistent
# ...
#o-saft.pl::checkdates(localhost, 443) {
#o-saft.pl:: valid-years = 0				<== inkonsistent
#o-saft.pl::checkdates() }
# ...
#o-saft.pl::check_nextproto: type=ALPN, np=http/1.1	<== inkonsistent
# ...
#o-saft.pl:: do=certversion cn ...			<== inkonsistent
#o-saft.pl::printdata(simple, localhost, 443) {

# --trace-ARG
#yeast.pl:  ARG: option=  --tracearg

# --trace-CMD  oder --trace-TIME
#yeast.pl 01:00:01 CMD: mod{
#yeast.pl 01:00:01 CMD: mod}
#-------------------------------------------------------------------------

# Version >= 24.01.24
#o-saft.pl 01:00:01 Net::SSLeay
#o-saft.pl 01:00:01 Net::SSLinfo::do_ssl_open(localhost,443,,) {
#o-saft.pl 01:00:01  do=certversion cn ...
#o-saft.pl 01:00:01 printdata(simple, localhost, 443) {
#-------------------------------------------------------------------------

use Data::Dumper qw(Dumper);
use OSaft::Text  qw(%STR print_pod);
use osaft;  # sets %cfg
# TODO: 01jan24: must use %::cmd, %::data, %::checks instead of %data; reason unknown

#_____________________________________________________________________________
#__________________________________________________________________ methods __|

sub trace_time  {
    #? compute timestamp, absolute or relative time
    #? return empty string if no --trace-time given
    # %cfg is set when this function is called, if not it's ok to die
    my $now = 0;
    return "" if (0 >= $cfg{'out'}->{'traceTIME'});
    if (defined $time0) {
        $now  = time();
        $now -= $time0 if (0 >= $cfg{'out'}->{'time_absolut'});
        $now  = 0 if (0 > $now);# fix runtime error: $now == -1
    }
    $now -= 3600;               # remove 1 hour, otherwise we get 01:00:00
    return sprintf(" %02s:%02s:%02s", (localtime($now))[2,1,0]);
} # trace_time

#sub __trace     { my @txt = @_; return sprintf("#%s%s %s", $cfg{'prefix_trace'}, trace_time(), "@txt"); }
sub __trace     { my @txt = @_; return sprintf("%s%s %s", $prefix_trace, trace_time(), "@txt"); }
sub trace_      { my @txt = @_; printf("%s"  , "@txt")           if (0 < $cfg{'trace'}); return; }
sub trace       { my @txt = @_; printf("%s\n", __trace($txt[0])) if (0 < $cfg{'trace'}); return; }
sub trace0      { my @txt = @_; printf("%s\n", __trace(""))      if (0 < $cfg{'trace'}); return; }
sub trace1      { my @txt = @_; printf("%s\n", __trace(@txt))    if (1 < $cfg{'trace'}); return; }
sub trace2      { my @txt = @_; printf("%s\n", __trace(@txt))    if (2 < $cfg{'trace'}); return; }
sub trace3      { my @txt = @_; printf("%s\n", __trace(@txt))    if (3 < $cfg{'trace'}); return; }
# if --trace-arg given
sub trace_arg   { my @txt = @_; printf("%s\n", __trace(" ARG: ", @txt)) if $cfg{'out'}->{'traceARG'}; return; }

# more methods see below: public test methods

#_____________________________________________________________________________
#_________________________________________________________ internal methods __|

sub __LINE      { return "#----------------------------------------------------"; }
sub __undef     { my $v = shift; $v = $STR{'UNDEF'} if not defined $v; return $v; }
    # empty string should not return $STR{'UNDEF'}
sub ___ARR      { return join(" ", "[", sort(@_), "]"); }
sub __TEXT      { return $prefix_verbose . "@_"; }
sub ___K_V      { my ($k, $v) = @_; return sprintf("%s%21s= %s", $prefix_verbose, $k, __undef($v)); }
sub _p_k_v      { printf("%s\n", ___K_V(@_));               return; }
sub _ptext      { printf("%s\n", __TEXT(@_));               return; }
sub _pline      { printf("%s\n", __TEXT(__LINE(), "@_"));   return; }
sub _pnull      { _ptext("value $STR{'UNDEF'} means that internal variable is not defined @_"); return; }
sub __trac      {
    # return variable according its type, understands: CODE, SCALAR, ARRAY, HASH
    my $ref  = shift;   # must be a hash reference
    my $key  = shift;
    my $data = "";
    if (not defined $ref->{$key}) {
        # undef is special, avoid perl warnings
        return ___K_V($key, "$STR{'UNDEF'}");
    }
    SWITCH: for (ref($ref->{$key})) {   # ugly but save use of $_ here
        /^$/    && do { $data .= ___K_V($key, $ref->{$key}); last SWITCH; };
        /CODE/  && do { $data .= ___K_V($key, "<<code>>");   last SWITCH; };
        /SCALAR/&& do { $data .= ___K_V($key, $ref->{$key}); last SWITCH; };
        /ARRAY/ && do { $data .= ___K_V($key, ___ARR(@{$ref->{$key}})); last SWITCH; };
        /HASH/  && do { last SWITCH if (2 >= $ref->{'trace'});  # print hashes for full trace only
                        $data .= __TEXT("# - - - - HASH: $key = {\n");
                        foreach my $k (sort keys %{$ref->{$key}}) {
                            my $val = "";
                            if (defined ${$ref->{$key}}{$k}) {
                               if ('ARRAY' eq ref(${$ref->{$key}}{$k})) {
                                   $val = "[ " . join(", ",@{$ref->{$key}{$k}}) . " ]";
                                       # ,-separated list hence not ___ARR()
                               } else {
                                   $val = join("-", ${$ref->{$key}}{$k});
                               }
                            }
                            $data .= ___K_V("    $k", $val . "\n");
                        };
                        $data .= __TEXT("# - - - - HASH: $key }");
                        last SWITCH;
                      };
        # DEFAULT
                        $data .= __TEXT($STR{WARN} . " user defined type '$_' skipped");
    } # SWITCH

    return $data;
} # __trac

sub _ptype { my $d = __trac(@_); printf("%s\n", $d) if ($d !~ m/^\s*$/); return; }
    #? print variable according its type, understands: CODE, SCALAR, ARRAY, HASH
    #  avoids printing of empty lines

#_____________________________________________________________________________
#_________________________________________ helper for internal test methods __|

# subs for formatted table
sub __data      { return (_is_member(shift, \@{$cfg{'commands'}}) > 0)   ? "*" : "?"; }
sub __data_title{ return sprintf("=%19s %s %s %s %s %s %s %s", @_); }
sub __data_head { return __data_title("key", "command", " %data  ", "%checks", "cmd-ch.", "short ", "intern ", ""); }
sub __data_line { return sprintf("=%19s+%s+%s+%s+%s+%s+%s+%s", "-"x19, "-"x7, "-"x7, "-"x7, "-"x7, "-"x7, "-"x7, "-"x7); }
sub __data_data { return sprintf("%20s\t%s\t%s\t%s\t%s\t%s\t%s\t%s", @_); }

# subs for fomated maps
sub __prot_option       {
    my $data;
    foreach my $key (sort keys %{$cfg{'openssl_option_map'}})  {
        $data .= __trac(\%{$cfg{'openssl_option_map'}}, $key) . "\n";
    }
    chomp  $data;   # remove last \n
    return $data;
} # __prot_option

sub __prot_version      {
    my $data;
    foreach my $key (sort keys %{$cfg{'openssl_version_map'}}) {
        $data .= __TEXT(sprintf("%21s= ", $key) . sprintf("0x%04X 0x%08x",
                                 ${$cfg{'openssl_version_map'}}{$key},
                                 ${$cfg{'openssl_version_map'}}{$key})
                        ) . "\n";
    }
    chomp  $data;   # remove last \n
    return $data;
} # __prot_version

#_____________________________________________________________________________
#____________________________________________________ internal test methods __|

sub _trace_test_help    {
    local $\ = "\n";
    printf("#%s:\n", (caller(0))[3]);
    print <<'EoT';

=== commands for internal testing ===
=
= Print list of commands for internal testing/information.
=
=   command/option  prints this information
=  ----------------+----------------------------------------------
=   --tests         this text
=   --test-init     data structure  %cfg after initialisation
=   --test-avail    overview of all available commands and checks
=   --test-maps     internal data strucures '%cfg{openssl}', '%cfg{ssleay}'
=   --test-prot     internal data according protocols
=   --test-vars     internal data structures using Data::Dumper
=   --test-regex    results for applying various texts to regex
=   --test-memory   overview of variables' memory usage
=   --test-methods  available methods for openssl in Net::SSLeay
=   --test-sclient  available options for 'openssl s_client' from Net::SSLeay
=   --test-sslmap   constants for SSL protocols from Net::SSLeay
=   --test-ssleay   information about Net::SSLeay capabilities
=   --test-ciphers-*    various ciphers listings; available with o-saft.pl only
=  ----------------+----------------------------------------------
=
EoT
    # o-saft.tcl --test-o-saft  # just for completeness, not used here
    # NOTE: description above should be similar to those in
    #       OSaft/Doc/help.txt
    return $data;
} # _trace_test_help

sub _trace_test_avail   {
    local $\ = "\n";
    printf("#%s:\n", (caller(0))[3]);
    print <<'EoT';

=== internal data structure: overview of commands, %data and %checks ===
=
= Print a simple overview of all available commands for  +info  and  +check .
= The purpose is to show if a proper key is defined in  %data and %checks  for
= each command from  %cfg{'commands'}  and vice versa.
=
=   column      description
=  ------------+--------------------------------------------------
=   key         key in %cfg{'commands'}
=   command     key (see above) available as command: +key
=   data        command returns %data  (part of +info)
=   checks      command returns %check (part of +check)
=   cmd-ch.     command listed in ...
=   short       desciption of command available as short text
=   intern      internal command only, not avaialable as +key
=  ------------+--------------------------------------------------
=
EoT

    my $old;
    my @yeast = ();     # list of potential internal, private commands
    my $cmd = " ";
    print __data_head();
    print __data_line();
    $old = "";
    foreach my $key
            (sort {uc($a) cmp uc($b)}
                @{$cfg{'commands'}}, keys %::data, keys %::shorttexts, keys %::checks
            )
            # we use sort case-insensitively, hence the BLOCK for comparsion
            # it also avoids the warning: sort (...) interpreted as function
    {
        next if ($key eq $old); # unique
        $old = $key;
        if ((not defined $::checks{$key}) and (not defined $::data{$key})) {
            push(@yeast, $key); # probably internal command
            next;
        }
        $cmd = "+" if (0 < _is_member($key, \@{$cfg{'commands'}})); # command available as is
        $cmd = "-" if ($key =~ /$cfg{'regex'}->{'SSLprot'}/i);      # all SSL/TLS commands are for checks only
        print __data_data(  #__/--- check value -------\    true : false  # column
            $key, $cmd,
            (defined $::data{$key})                ? __data( $key) : " ", # data
            (defined $::checks{$key})                     ?   "*"  : " ", # checks
            (_is_member($key, \@{$dbx{'cmd-check'}}) > 0) ?   "*"  : "!", # cmd-ch.
            (defined $::shorttexts{$key})                 ?   "*"  : " ", # short
            (_is_cfg_intern($key))                        ?   "I"  : " ", # intern
            "",
#           (defined $checks{$key}->{score}) ? $checks{$key}->{score} : ".",
# score removed 23.12.23
#=   .  no score defined in %checks{key}
            );
    }
    print __data_line();
    print __data_head();
    print <<'EoT';
=
=   +  command (key) present
=   I  command is an internal command or alias (ok in column 'intern')
=   -  command (key) used internal for checks only (ok in column 'command')
=   *  key present
=      key not present
=   ?  key in %data present but missing in $cfg{commands}
=   !  key in %cfg{cmd-check} present but missing in redefined %cfg{cmd-check}
=
= Some commands (keys) in column  cmd-ch.  marked  !  are not considered an
= error 'cause they are ancient checks like hastls10_old, or special checks
= like extensions, or are just for documentation like cps_valid.
=
= A short text should be available for  each command and for all data keys,
# except for internal commands (columns intern) and following:
=      cn_nosni, ext_*, valid_*
=
= Internal or summary commands:
EoT
    print "=      " . join(" ", @yeast) . "\n";
    return;
} # _trace_test_avail

sub _trace_test_init    {
    local $\ = "\n";
    local $Data::Dumper::Deparse=1; # parse code, see man Data::Dumper
    my $line = "#--------------------+-------------------------------------------";
    printf("#%s:\n", (caller(0))[3]);
    print <<'EoT';

=== internal data structure: initialisation of %cfg, %data and %checks ===
=
= Print initialised data structure  %data and %checks  after all  command-line
= options have been applied.
=
EoT
#ah not ok: use Sub::Identify ':all';
    _pline("%cfg {");  # only data which influences initialisations
    _ptext("#                key | value");
    _ptext($line);
    _p_k_v("ARGV", ___ARR(@{$cfg{'ARGV'}}));
    _pline("%cfg{use} {");
    foreach my $key (sort keys %{$cfg{'use'}}) {
        _p_k_v($key, $cfg{'use'}{$key});
    }
    _pline("%cfg{use} }");
    _ptext($line);
    _pline("%cfg }");
    _pline("%data {");
    _ptext("#                key | value (function code)");
    _ptext($line);
    ## no critic qw(Variables::ProhibitPackageVars); they are intended here
    foreach my $key (sort keys %::data) { # ugly and slow code
        my $code = Dumper($::data{$key}->{val});
        # use Dumper() to get code, returns something like example 1:
        #     $VAR1 = sub {
        #                 package OSaft::Data;
        #                 use warnings;
        #                 use strict;
        #                 Net::SSLinfo::version($_[0], $_[1]);
        #             };
        # or example 2:
        #     $VAR1 = sub {
        #         'txt'	=> 'Target default DTLS 0.9 cipher',
        #         'val'	=> sub {
        #             BEGIN {${^WARNING_BITS} = "\x55\x55\ ... x55"}
        #             use strict;
        #             return $main::prot{$ssl}{'default'};
        #         }
        #     },
        # the line with "package" occours only if the data is in another namespace
        # we only want the code line, hence remove the others
        #dbx# print "##CODE= $code";
        $code =~ s/^\$VAR.*//;                  # ex 1, 2
        $code =~ s/(}[;,])?\s*$//gn;            # ex 1, 2
        $code =~ s/use\s*(strict|warnings);//gn;# ex 1, 2
        $code =~ s/package\s*.*;//g;            # ex 1
        $code =~ s/BEGIN\s*.*//g;               # ex 2
        $code =~ s/return\s*//g;                # ex 2
        $code =~ s/\n//g;
        $code =~ s/^\s*//g; # anything else, like: 'txt' lines
        _p_k_v($key, $code);
    }
    _ptext($line);
    _pline("%data }");
    _pline("%checks {");
    _ptext("#                key | value");
    _ptext($line);
    foreach my $key (sort keys %::checks) {
        _p_k_v($key, $::checks{$key}->{val});
    }
    _ptext($line);
    _pline("%checks }");
    return;
} # _trace_test_init

sub _trace_test_maps    {
    printf("#%s:\n", (caller(0))[3]);
    print <<'EoT';

=== internal data structure %cfg{openssl}, %cfg{ssleay} ===
=
= Print internal mappings for openssl functionality (mainly options).
=
EoT
    local $\ = "\n";
    my $data = Net::SSLinfo::test_sslmap();
       $data =~ s/^#/#$cfg{'me'}/smg;
    print $data;
    _pline("%cfg{openssl_option_map} {");
    print __prot_option();
    _pline("%cfg{openssl_version_map} {");
    print __prot_version();
    return;
} # _trace_test_maps

sub _trace_test_prot    {
    printf("#%s:\n", (caller(0))[3]);
    print <<'EoT';

=== internal data structure according protocols ===
=
= Print information about SSL/TLS protocols in various internal variables.
=
EoT
    local $\ = "\n";
    my $ssl = $cfg{'regex'}->{'SSLprot'};
    _pnull("\n");
    _pline("%cfg {");
    foreach my $key (sort keys %cfg) {
        # targets= is array of arrays, prints ARRAY ref here only
        _ptype(\%cfg, $key) if ($key =~ m/$ssl/);
    }
    _pline("}");
    _pline("%cfg{openssl_option_map} {");
    print __prot_option();
    _pline("}");
    _pline("%cfg{openssl_version_map} {");
    print __prot_version();
    _pline("}");
    # %check_conn and %check_dest are temporary and should be inside %checks
    _pline("%checks {");
    foreach my $key (sort keys %checks) {
        # $checks{$key}->{val} undefined at beginning
        _ptext(sprintf("%14s= ", $key) . $checks{$key}->{txt}) if ($key =~ m/$ssl/);
    }
    _pline("}");
    _pline("%shorttexts {");
    foreach my $key (sort keys %shorttexts) {
        _ptext(sprintf("%14s= ",$key) . $shorttexts{$key}) if ($key =~ m/$ssl/);
    }
    _pline("}");
    return;
} # _trace_test_prot

sub _trace_test_methods {
    printf("#%s:\n", (caller(0))[3]);
    print <<'EoT';

=== internal list of methods to call openssl ===
=
= Print available methods in Net::SSLeay.
=
EoT
    my $list = Net::SSLinfo::test_methods();
       $list =~ s/ /\n# /g;
    print "# $list";
    return;
} # _trace_test_methods

sub _trace_test_sclient {
    printf("#%s:\n", (caller(0))[3]);
    print <<'EoT';

=== internal list of openssl s_client options ===
=
= Print available options for 'openssl s_client' from Net::SSLeay.
=
EoT
    my $list = Net::SSLinfo::test_sclient();
       $list =~ s/ /\n# /g;
    print "# $list";
    return;
} # _trace_test_sclient

sub _trace_test_sslmap  {
    printf("#%s:\n", (caller(0))[3]);
    print <<'EoT';

=== internal list of constants for SSL protocols ===
=
= Print available constants for SSL protocols in Net::SSLeay.
=
EoT
    print Net::SSLinfo::test_sslmap();
    return;
} # _trace_test_sslmap

sub _trace_test_ssleay  {
    printf("#%s:\n", (caller(0))[3]);
    print <<'EoT';
 
=== internal data of from Net::SSLeay ===
=
= Print information about Net::SSLeay capabilities.
=
EoT
    print Net::SSLinfo::test_ssleay();
    return;
} # _trace_test_ssleay

sub _trace_test_memory  {
    #? print overview of memory usage of variables
    # This is not part of the functionality of O-Saft itself, but more like
    # a quality or performance check.
    # I.g. it should be implemented in makefiles or alike, but is done here
    # in the source because the variables are avaiable in the source only.
    printf("#%s:\n", (caller(0))[3]);
    require Devel::Size;    # require instead of use to avoid dependencies (i.e. in checkAllCiphers.pl)
    my %types = (   # TODO: not yet used
        'ARRAY'   => '@',
        'CODE'    => '{',
        'FORMAT'  => '#',
        'GLOB'    => '*',
        'HASH'    => '%',
        'IO'      => '&',
        'LVALUE'  => '=',
        'REF'     => '\\',
        'REGEXP'  => '/',
        'SCALAR'  => '$',
        'VSTRING' => '"',
    );
    print <<'EoT';

=== memory usage of internal variables ===
=
= Use  --v  to get more details.
=
EoT
    if (0 < $cfg{'trace'}) {
        foreach my $k (keys %cfg) {
	    printf("%6s\t%s\n", Devel::Size::total_size(\$cfg{$k}),    "%cfg{$k}");
        }
        foreach my $k (keys %::checks) {
	    printf("%6s\t%s\n", Devel::Size::total_size(\$checks{$k}), "%checks{$k}");
        }
        #foreach my $k (keys %ciphers) {    # useless, as each entry is about 2k
	#    printf("%6s\t%s\n", Devel::Size::total_size(\$ciphers{$k}), "%ciphers{$k}");
        #}
        foreach my $k (keys %dbx) {
	    printf("%6s\t%s\n", Devel::Size::total_size(\$dbx{$k}),    "%dbx{$k}");
        }
        #foreach my $k (keys %data) {       # most entries report 42k, which is wrong
	#    printf("%6s\t%s\n", Devel::Size::total_size(\$data{$k}), "%data{$k}");
        #}
    }
    my $bytes = 0;
    my $line  = "=------+----------------";
    # get all global variables and grep for our ones
    # ugly code, but generic
    print "= Bytes variable\n$line";
    foreach my $v (sort keys %main::) {
        #print Dumper $v; # liefert den gesamten Hash
        next if ("*{$main::{$v}}" !~ m/\*main::/);
        next if ($main::{$v} =~ m/::$/);           # avoid "Segmentation fault"
        next if (not grep {/^(cfg|check|cipher|cmd|data|dbx|info|osaft|short|text)/} $v) ;
        next if (    grep {/^check(cipher|http)/} $v) ; # avoid "Segmentation fault"
        # TODO: my $typ = ref($main::{$v}); # not yet working
        #dbx print "K $v $main::{$v} => $t";
        my $size = Devel::Size::total_size(\$main::{$v});
        $bytes += $size;
        printf("%7s\t%s\n", $size, $v);#if (exists $main::{$v});
    }
    print "$line";
    printf("%7s\t(%2.2f MB) total\n", $bytes, $bytes/1024/1024);
    # the traditional way ...
    #print "%cfg    : ", Devel::Size::total_size(\%cfg);
    #print "%data   : ", Devel::Size::total_size(\%data);
    #print "%checks : ", Devel::Size::total_size(\%checks);
    #print "%ciphers: ", Devel::Size::total_size(\%ciphers);
    #print "\@results: ", Devel::Size::total_size(\@cipher_results);
    #print "%text   : ", Devel::Size::total_size(\%text);
    #print "%_SSLinfo   : ", Devel::Size::total_size(\%Net::SSLinfo::_SSLinfo);
    return;
} # _trace_test_memory

sub __trace_dump_var    {
    #? print varable name and it's content using Data::Dumper()
    #  unfortunately Data::Dumper is not able to print the name of the variable
    #  hence this cumbersome approach (see settings in calling function)
    my $type = shift;
    my $var  = shift;
    my $name = "$type$var";
    _pline("$name {");
    $var = $::{$var};   # see NOTE: 01jan24
    printf("%s = %s\n", $name, Dumper($$var))  if ('$' eq $type);
    printf("%s = %s\n", $name, Dumper(\%$var)) if ('%' eq $type);
    printf("%s = %s\n", $name, Dumper(\@$var)) if ('@' eq $type);
    _pline("$name }");
    return;
} # __trace_dump_var

sub _trace_test_vars    {
    printf("#%s:\n", (caller(0))[3]);
    local $\ = "\n";
    # for details on used $Data::Dumper:: varaibles, see man Data::Dumper
    local $Data::Dumper::Deparse    = 1;# we want the code references
        # TODO: use Deparse=1 and filter code, see _trace_test_init()
    local $Data::Dumper::Sparseseen = 1;# not needed here
    local $Data::Dumper::Purity     = 0;# no warnings for "DUMMY"
    local $Data::Dumper::Sortkeys   = 1;# 
    local $Data::Dumper::Quotekeys  = 1;# default, but ensure it's set
    local $Data::Dumper::Indent     = 1;# 2 with more indentation
    local $Data::Dumper::Pair   = "\t=> ";  # slightly better formatting
#   local $Data::Dumper::Pad    = __TEXT();# not used, output is valid perl
#   local $Data::Dumper::Varname= '%prot';
    # Varname is just replace VAR, means $%prot1 is used istead of $VAR1, which
    # is not exactly what we want, hence Terse=1 is used  and the variable name
    # is written verbatim
    local $Data::Dumper::Terse      = 1;

    print <<'EoT';

=== internal data structures %ciphers %prot %cfg %data %info %checks ===
=
= Print initialised internal data structures using Perl's Data::Dumper.
=
EoT
    __trace_dump_var('$', 'cipher_results');
    __trace_dump_var('%', 'ciphers');
    __trace_dump_var('%', 'ciphers_desc');
    __trace_dump_var('%', 'prot');
    __trace_dump_var('%', 'cfg');
    __trace_dump_var('%', 'data');
    __trace_dump_var('%', 'info');
    __trace_dump_var('%', 'checks');
    return;
} # _trace_test_vars

#_____________________________________________________________________________
#______________________________________________________ public test methods __|

sub trace_ciphers_list  {
    #? print ciphers fromc %cfg (output optimised for +cipher)
    return if (0 >= $cfg{'trace'});
    my $need = shift;
    _pline("ciphers {");
    my $_cnt = scalar @{$cfg{'ciphers'}};
    my $ciphers = "@{$cfg{'ciphers'}}"; # not yet used
    _ptext("  _need_cipher= $need");
    if (0 < $need) {
        # avoid printing huge lists
        my @range;
        if ($cfg{'cipherrange'} =~ m/(full|huge|long|safe|rfc|intern)/i) {
            # avoid huge (useless output)
            $_cnt = 0xffffff;
            $_cnt = 0x2fffff if ($cfg{'cipherrange'} =~ m/safe/i);
            $_cnt = 0xffff   if ($cfg{'cipherrange'} =~ m/long/i);
            $_cnt = 0xffff   if ($cfg{'cipherrange'} =~ m/huge/i);
            $_cnt = 2051     if ($cfg{'cipherrange'} =~ m/rfc/i);   # estimated count
            $_cnt = 2640     if ($cfg{'cipherrange'} =~ m/intern/i);# estimated count
            @range = "<<huge list not printed>>";
        } else {
            # expand smaller list
            @range = osaft::get_ciphers_range('TLSv13', $cfg{'cipherrange'});
               # NOTE: osaft::get_ciphers_range() first arg is the SSL version,
               #       which is usually unknown here, hence TLSv13 is passed
            $_cnt = scalar @range;
        }
        $_cnt = sprintf("%5s", $_cnt);  # format count
        _ptext("   cmd{extciphers}= " . $::cmd{'extciphers'} . " (1=use cipher from openssl)");
        _ptext("      starttls= " . $cfg{'starttls'});
        _ptext("    ciphermode= " . $cfg{'ciphermode'});
        _ptext(" cipherpattern= " . $cfg{'cipherpattern'});
        _ptext("   cipherrange= " . $cfg{'cipherrange'});
        # format range text
        foreach my $txt (split(/\n/, $cfg{'cipherranges'}->{$cfg{'cipherrange'}})) {
            next if $txt =~ m/^\s*$/;
            $txt =~ s/^\s*/                /;
            _ptext($txt);
        }
        _ptext(" $_cnt ciphers= @range");
        _ptext("     cipher_dh= " . $cfg{'cipher_dh'});
        _ptext("    cipher_md5= " . $cfg{'cipher_md5'});
        _ptext("   cipher_ecdh= " . $cfg{'cipher_ecdh'});
        _ptext("   cipher_npns= " . ___ARR(@{$cfg{'cipher_npns'}}));
        _ptext("  cipher_alpns= " . ___ARR(@{$cfg{'cipher_alpns'}}));
    }
    _pline("ciphers }");
    return;
} # trace_ciphers_list

sub trace_targets       {
    #? print information about targets to be processed
    # full list if 1<trace
    my @targets = @_;
    return if (0 >= $cfg{'trace'});
    #print " === print internal data structures for a targets === ";
    if (2 > $cfg{'trace'}) { # simple list
        printf("%s%14s= [ ", $cfg{'prefix_trace'}, "targets");
        foreach my $target (@targets) {
            next if (0 == @{$target}[0]);       # first entry conatins default settings
            printf("%s:%s%s ", @{$target}[2..3,6]);
               # the perlish way instead of get_target_{host,port,path}
        }
        printf("]\n");
    } else {
        printf("%s%14s targets = [\n", $cfg{'prefix_trace'}, "# - - - -ARRAY");
        printf("%s#  Index %6s %24s : %5s %10s %5s %-16s %s\n",
                $cfg{'prefix_trace'}, "Prot.", "Hostname or IP", "Port", "Auth", "Proxy", "Path", "Orig. Parameter");
        foreach my $target (@targets) {
            #next if (0 == @{$target}[0]);       # first entry conatins default settings
            printf("%s   [%3s] %6s %24s : %5s %10s %5s %-16s %s\n", $cfg{'prefix_trace'}, @{$target}[0,1..7]);
        }
        printf("%s%14s ]\n", $cfg{'prefix_trace'}, "# - - - -ARRAY");
    }
    return;
} # trace_targets

sub trace_init  {   ## no critic qw(Subroutines::ProhibitExcessComplexity)
    #? print important content of %cfg and %cmd hashes
    #? more output if 1<trace; full output if 2<trace
    return if (0 >= $cfg{'trace'});
    local $\ = "\n";
    my $arg = " (does not exist)";
    ## no critic qw(Variables::ProhibitPackageVars); they are intended here
    if (-f $cfg{'RC-FILE'}) { $arg = " (exists)"; }
    _ptext("!!Hint: use --trace=2  to see Net::SSLinfo variables") if (2 > $cfg{'trace'});
    _ptext("!!Hint: use --trace=2  to see external commands")      if (2 > $cfg{'trace'});
    _ptext("!!Hint: use --trace=3  to see full %cfg")              if (3 > $cfg{'trace'});
    _pnull();
    _ptext("#") if (3 > $cfg{'trace'});
    _pline("");
    #_p_k_v("trace_init::SID", $SID_trace) if (2 < $cfg{'trace'}); # 24.01.24 removed
    _p_k_v("$0", main::_VERSION()); ## no critic qw(Subroutines::ProtectPrivateSubs)
        # TBD: $0 is same as $ARG0 but wrong when called as standalone
    # official VERSIONs, not those of the current files !
    _p_k_v("::osaft",       ($osaft::VERSION || $STR{'UNDEF'}));
    _p_k_v("Net::SSLhello", ($Net::SSLhello::VERSION || $STR{'UNDEF'}));
    _p_k_v("Net::SSLinfo",  ($Net::SSLinfo::VERSION  || $STR{'UNDEF'}));
    # quick info first
    _p_k_v("RC-FILE", $cfg{'RC-FILE'} . $arg);
    _p_k_v("--rc",    ((grep{/(?:--rc)$/i}     @ARGV) > 0)? 1 : 0);
    _p_k_v("--no-rc", ((grep{/(?:--no.?rc)$/i} @ARGV) > 0)? 1 : 0);
    _p_k_v("verbose", $cfg{'verbose'});
    _p_k_v("trace",  "$cfg{'trace'}, traceARG=$cfg{'out'}->{'traceARG'}, traceKEY=$cfg{'out'}->{'traceKEY'}, traceTIME=$cfg{'out'}->{'traceTIME'}");
    _p_k_v("time_absolut", $cfg{'out'}->{'time_absolut'});
    _p_k_v("dbx{file}", "[ " . join(", ", @{$dbx{'file'}}) . " ]");

    if (1 < $cfg{'trace'}) {
        _pline("Net::SSLinfo {");
        _p_k_v("::trace",         $Net::SSLinfo::trace);
        _p_k_v("::linux_debug",   $Net::SSLinfo::linux_debug);
        _p_k_v("::slowly",        $Net::SSLinfo::slowly);
        _p_k_v("::timeout",       $Net::SSLinfo::timeout);
        _p_k_v("::use_openssl",   $Net::SSLinfo::use_openssl);
        _p_k_v("::use_sclient",   $Net::SSLinfo::use_sclient);
        _p_k_v("::use_extdebug",  $Net::SSLinfo::use_extdebug);
        _p_k_v("::use_nextprot",  $Net::SSLinfo::use_nextprot);
        _p_k_v("::use_reconnect", $Net::SSLinfo::use_reconnect);
        _p_k_v("::use_SNI",       $Net::SSLinfo::use_SNI);
        _p_k_v("::use_http",      $Net::SSLinfo::use_http);
        _p_k_v("::no_cert",       $Net::SSLinfo::no_cert);
        _p_k_v("::no_cert_txt",   $Net::SSLinfo::no_cert_txt);
        _p_k_v("::protos_alpn",   $Net::SSLinfo::protos_alpn);
        _p_k_v("::protos_npn",    $Net::SSLinfo::protos_npn);
        _p_k_v("::sclient_opt",   $Net::SSLinfo::sclient_opt);
        _p_k_v("::ignore_case",   $Net::SSLinfo::ignore_case);
        _p_k_v("::timeout_sec",   $Net::SSLinfo::timeout_sec);
        _pline("Net::SSLinfo }");
    }

    _pline("%cmd {");
    if (2 > $cfg{'trace'}) {    # user-friendly information
        _ptext("          path= " . ___ARR(@{$::cmd{'path'}}));
        _ptext("          libs= " . ___ARR(@{$::cmd{'libs'}}));
        _ptext("     envlibvar= $::cmd{'envlibvar'}");
        _ptext("       timeout= $::cmd{'timeout'}");
        _ptext("       openssl= $::cmd{'openssl'}");
    } else {    # full information
        foreach my $key (sort keys %::cmd) { _ptype(\%::cmd, $key); }
    }
    _ptext("    extopenssl= $::cmd{'extopenssl'}");   # user-friendly always
    _ptext("use cipher from openssl= $::cmd{'extciphers'}");  # dito.
    _pline("%cmd }");

    if (1 < $cfg{'trace'}) {    # full information
        _pline("complete %cfg {");
        foreach my $key (sort keys %cfg) {
            if ($key =~ m/(hints|openssl|ssleay|sslerror|sslhello|regex|^out|^use)$/) { # |data
                # TODO: ugly data structures ... should be done by _p_k_v()
                _ptext("# - - - - HASH: $key = {");
                foreach my $k (sort keys %{$cfg{$key}}) {
                    if ($key =~ m/openssl/) {
                        _p_k_v($k, ___ARR(@{$cfg{$key}{$k}}));
                    } else {
                        #_p_k_v($k, $cfg{$key}{$k});
                        _ptype($cfg{$key}, $k);
                    };
                };
                _ptext("# - - - - HASH: $key }");
            } else {
                if ($key =~ m/targets/) {   # TODO: quick&dirty to get full data
                    trace_targets(@{$cfg{'targets'}});
                } else {
                    if ("time0" eq $key and defined $ENV{'OSAFT_MAKE'}) {
                        # SEE Make:OSAFT_MAKE (in Makefile.pod)
                        my $t0 = $cfg{'time0'};
                        $cfg{'time0'} = $STR{MAKEVAL};
                        _ptype(\%cfg, $key);
                        $cfg{'time0'} = $t0;
                    } else {
                        _ptype(\%cfg, $key);
                    }
                }
            }
        }
        _pline("%cfg }");
        return;
    }
    # else  user-friendly information
    my $sni_name = __undef($cfg{'sni_name'});   # default is Perl's undef
    my $port     = __undef($cfg{'port'});       # default is Perl's undef
    _pline("user-friendly cfg {");
    _ptext("      ca_depth= $cfg{'ca_depth'}") if defined $cfg{'ca_depth'};
    _ptext("       ca_path= $cfg{'ca_path'}")  if defined $cfg{'ca_path'};
    _ptext("       ca_file= $cfg{'ca_file'}")  if defined $cfg{'ca_file'};
    _ptext("       use_SNI= $Net::SSLinfo::use_SNI, force-sni=$cfg{'use'}->{'forcesni'}, sni_name=$sni_name");
    _ptext("  default port= $port (last specified)");
    trace_targets(@{$cfg{'targets'}});
    _ptext("     use->http= $cfg{'use'}->{'http'}");
    _ptext("    use->https= $cfg{'use'}->{'https'}");
    _ptext(" out->hostname= $cfg{'out'}->{'hostname'}");
    _ptext("   out->header= $cfg{'out'}->{'header'}");
    foreach my $key (qw(format legacy starttls starttls_delay slow_server_delay cipherrange)) {
        _p_k_v($key, $cfg{$key});
    }
    _ptext("        cipher= " . ___ARR(@{$cfg{'cipher'}}));
    foreach my $key (qw(starttls_phase starttls_error)) {
        _ptext(      "$key= " . ___ARR(@{$cfg{$key}}));
    }
    _ptext("   SSL version= " . ___ARR(@{$cfg{'version'}}));
    printf("%s",___K_V("SSL versions", "[ "));  # no \n !
    printf("%s=%s ", $_, $cfg{$_}) foreach (@{$cfg{'versions'}});
    printf("]\n");
    _ptext(" special SSLv2= null-sslv2=$cfg{'use'}->{'nullssl2'}, ssl-lazy=$cfg{'use'}->{'ssl_lazy'}");
    _ptext(" ignore output= " . ___ARR(@{$cfg{'ignore-out'}}));
    _ptext(" user commands= " . ___ARR(@{$cfg{'commands_usr'}}));
    _ptext("given commands= " . ___ARR(@{$cfg{'done'}->{'arg_cmds'}}));
    _ptext("      commands= " . ___ARR(@{$cfg{'do'}}));
    _pline("user-friendly cfg }");
    _ptext("(more information with: --trace=2  or  --trace=3 )") if (1 > $cfg{'trace'});
    # $cfg{'ciphers'} may not yet set, print with Trace::trace_ciphers_list()
    return;
} # trace_init

sub trace_exit  {
    #? print collected information at program exit
    return if (0 >= $cfg{'trace'});
    _p_k_v("cfg'exitcode'", $cfg{'use'}->{'exitcode'});
    _p_k_v("exit status", (($cfg{'use'}->{'exitcode'}==0) ? 0 : $checks{'cnt_checks_no'}->{val}));
    _ptext("internal administration ..");
    _pline('@cfg{done} {');
    foreach my $key (sort keys %{$cfg{'done'}}) {
        _ptype(\%{$cfg{'done'}}, $key);
    }
    _pline('@cfg{done} }');
    return;
} # trace_exit

sub trace_args  {
    #? print information about command line arguments
    # using trace_arg() may be a performance penulty, but it's trace anyway ...
    return if (0 >= $cfg{'out'}->{'traceARG'});
    _pline("ARGV {");
    trace_arg("# summary of all arguments and options from command-line");
    trace_arg("       called program ARG0= " . $cfg{'ARG0'});
    trace_arg("     passed arguments ARGV= " . ___ARR(@{$cfg{'ARGV'}}));
    trace_arg("                   RC-FILE= " . $cfg{'RC-FILE'});
    trace_arg("      from RC-FILE RC-ARGV= ($#{$cfg{'RC-ARGV'}} more args ...)");
    if (2 > $cfg{'trace'}) {
    trace_arg("      !!Hint:  use --trace=2 to get the list of all RC-ARGV");
    trace_arg("      !!Hint:  use --trace=3 to see the processed RC-ARGV");
                  # NOTE: ($cfg{'trace'} does not work here
    }
    trace_arg("      from RC-FILE RC-ARGV= " . ___ARR(@{$cfg{'RC-ARGV'}})) if (1 < $cfg{'trace'});
    my $txt = "[ ";
    foreach my $target (@{$cfg{'targets'}}) {
        next if (0 == @{$target}[0]);   # first entry conatins default settings
        $txt .= sprintf("%s:%s ", @{$target}[2..3]); # the perlish way
    }
    $txt .= "]";
    trace_arg("         collected targets= " . $txt);
    if (2 < $cfg{'trace'}) {
    trace_arg(" #--v { processed files, arguments and options");
    trace_arg("    read files and modules= ". ___ARR(@{$dbx{file}}));
    trace_arg("processed  exec  arguments= ". ___ARR(@{$dbx{exe}}));
    trace_arg("processed normal arguments= ". ___ARR(@{$dbx{argv}}));
    trace_arg("processed config arguments= ". ___ARR(map{"`".$_."'"} @{$dbx{cfg}}));
    trace_arg(" #--v }");
    }
    _pline("ARGV }");
    return;
} # trace_args

sub trace_rcfile {
    #? print content read from RC-FILE ## NOT YET USED ##
    return if (0 >= $cfg{'trace'});
    _pline("RC-FILE {");
    _pline("RC-FILE }");
    return;
} # trace_rcfile {

sub trace_test  {
    #? dispatcher for internal tests, initiated with option --test-*
    my $arg = shift;    # normalised option, like --testinit, --testcipherlist
    _ptext($arg);
    if ($arg =~ /^--test.?ciphers?.?list$/) {   # allow not normalised also
        # --test-ciphers-list is for printing ciphers in common --v format, it
        # also honors the option  --cipherrange=  additonaly it relies on some
        # special settings in $cfg{};  +cipher  must be added to $cfg{'do'} to
        # enforce printing, also at least one TLS version must be used;
        # changing the configuration here should  not harm other functionality
        # changing the $cfg{} here should not harm other functionality because
        # _trace_test() is for debugging only and will exit then
        push(@{$cfg{'do'}}, 'cipher'); # enforce printing cipher informations
        push(@{$cfg{'version'}}, 'TLSv1') if (0 > $#{$cfg{'version'}});
        $cfg{'trace'} = 1;
        trace_ciphers_list(1); # simulate _need_cipher()
        return;
    }
    OSaft::Ciphers::show($arg)  if ($arg =~ /^--test.?cipher/);
    _trace_test_help()          if ('--test'          eq $arg);
    _trace_test_help()          if ('--tests'         eq $arg);
    _trace_test_sclient()       if ('--testsclient'   eq $arg); # Net::SSLinfo
    _trace_test_ssleay()        if ('--testssleay'    eq $arg); # Net::SSLinfo
    _trace_test_sslmap()        if ('--testsslmap'    eq $arg); # Net::SSLinfo
    _trace_test_methods()       if ('--testmethods'   eq $arg); # Net::SSLinfo
    _trace_test_memory()        if ('--testmemory'    eq $arg);
    $arg =~ s/^[+-]-?tests?[._-]?//; # remove --test
    osaft::test_cipher_regex()  if ('regex'           eq $arg);
    _trace_test_avail()         if ($arg =~ m/^avail(?:able)?$/);
    _trace_test_init()          if ('init'            eq $arg);
    _trace_test_maps()          if ('maps'            eq $arg);
    _trace_test_prot()          if ('prot'            eq $arg);
    _trace_test_vars()          if ('vars'            eq $arg);
    return;
} # trace_test

#_____________________________________________________________________________
#_____________________________________________________________________ main __|

sub _main_trace {
    my $arg = shift || "--help";    # without argument print own help
    $cfg{'time0'} = $STR{MAKEVAL} if (defined $ENV{'OSAFT_MAKE'});
        # SEE Make:OSAFT_MAKE (in Makefile.pod)
        # dirty hack here which asumes that _main_trace() is called to print
        # information only and does not need time0
    ## no critic qw(InputOutput::RequireEncodingWithUTF8Layer)
    #   see t/.perlcriticrc for detailed description of "no critic"
    #  SEE Perl:binmode()
    binmode(STDOUT, ":unix:utf8");
    binmode(STDERR, ":unix:utf8");
    print_pod($0, __FILE__, $SID_trace) if ($arg =~ m/--?h(elp)?$/x);   # print own help
    # else
    # ----------------------------- commands
    if ($arg =~ m/^--?trace/)           { $trace++; }
    if ($arg eq 'version')              { print "$SID_trace\n"; exit 0; }
    if ($arg =~ m/^[-+]?V(ERSION)?$/)   { print "$VERSION\n";   exit 0; }
    if ($arg =~ m/--tests?$/)           { _trace_test_help();   exit 0; }
    if ($arg =~ m/--(yeast|test)[_.-]?(.*)/) {
        $arg = "--test-$2";
        printf("#$0: direct testing not yet possible, please try:\n   o-saft.pl $arg\n");
    }
    exit 0;
} # _main_trace

sub trace_done      {}; # dummy to check successful include

#_____________________________________________________________________________
#_____________________________________________________ public documentation __|

=pod

=encoding utf8

=head1 NAME

OSaft::Trace.pm - module for tracing o-saft.pl


=head1 SYNOPSIS

=over 2

=item require "OSaft/Trace.pm"; # from within Perl code

=item use OSaft::Trace;         # from within Perl code

=item OSaft/Trace.pm <L<OPTIONS|OPTIONS>>  # on command line

=back


=head1 OPTIONS

=over 2

=item --help

=item --tests

List available commands or options for internal testing.

=item --test-ciphers-list

=item --test-regex

=item --test-avail

=item --test-init

=item --test-maps

=item --test-prot

=item --test-vars

See  I<--tests>  for description of these options.

=back


=head1 DESCRIPTION

Defines all functions needed for trace and debug output in  L<o-saft.pl|o-saft.pl>.


=head1 METHODS

=head2 Functions for internal testing; initiated with option  I<--test-*>
For example  I<--test-maps>  calls  C<_trace_test_maps()>.

=head3 _trace_test_help( )

=head3 _trace_test_avail( )

=head3 _trace_test_init( )

=head3 _trace_test_maps( )

=head3 _trace_test_prot( )

=head3 _trace_test_vars( )

=head3 _trace_test_methods( )

=head3 _trace_test_sclient( )

=head3 _trace_test_sslmap( )

=head3 _trace_test_ssleay( )

=head3 _trace_test_memory( )

=head2 Public functions

Hint: if functions are not used in the calling program, they should be defined
as empty stub there, for example:

    sub trace_init() {}

=head3 OSaft::Trace::trace_ciphers_list( )

=head3 OSaft::Trace::trace_targets( )

=head3 OSaft::Trace::trace_rcfile( )

=head3 OSaft::Trace::trace_arg( )

=head3 OSaft::Trace::trace_args( )

=head3 OSaft::Trace::trace_init( )

=head3 OSaft::Trace::trace_exit( )

=head3 OSaft::Trace::trace( )

=head3 OSaft::Trace::trace2( )

=head3 OSaft::Trace::trace3( )

=head3 OSaft::Trace::trace4( )

=head3 trace_test( )

=head2 VARIABLES

Variables which may be used herein must be defined as `our' in L<o-saft.pl|o-saft.pl>:

=head3 $SID_main

=head3 %data

=head3 %cfg, i.e. trace, traceARG, traceKEY, time_absolut, verbose

=head3 %checks

=head3 %dbx

=head3 $time0


=head1 SPECIALS

If you want to do special debugging, you can define proper functions here.
They don't need to be defined in L<o-saft.pl|o-saft.pl> if they are used only
here. In that case simply call the function in C<trace_init> or C<trace_exit>
they are called at beginning and end of L<o-saft.pl|o-saft.pl>.
It's just important that  L<o-saft.pl|o-saft.pl>  was called with either the
I<--v> or any I<--trace*>  option, which then loads this file automatically.


=head1 VERSION

2.3 2024/01/08

=head1 AUTHOR

23-nov-23 Achim Hoffmann

=cut

## PACKAGE }

#_____________________________________________________________________________
#_____________________________________________________________________ self __|

_main_trace(@ARGV) if (not defined caller);

1;
