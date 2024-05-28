#!/usr/bin/perl
## PACKAGE {

#!# Copyright (c) 2024, Achim Hoffmann
#!# This  software is licensed under GPLv2. Please see o-saft.pl for details.

package OTrace;

# HACKER's INFO
#       Following (internal) functions from o-saft.pl are used:
#       _is_cfg_intern()
#       _is_member()

# for description of "no critic" pragmas, please see  t/.perlcriticrc  and
# SEE Perl:perlcritic

## no critic qw(Subroutines::RequireArgUnpacking)
#       Parameters are ok for trace output.

## no critic qw(RegularExpressions::RequireExtendedFormatting)

## no critic qw(Variables::ProhibitPackageVars)
#       Because variables are defined herein and global variables are used.

## no critic qw(TestingAndDebugging::RequireUseStrict)
#       `use strict;' not useful here, as mainly global variables are used.

## no critic qw(ValuesAndExpressions::ProhibitMagicNumbers)
#       Severity 2 only; otherwise  "perlcritic -p t/.perlcriticrc"  reports
#       effusive messages for that directive.

use warnings;
# use strict;

no warnings 'redefine'; ## no critic qw(TestingAndDebugging::ProhibitNoWarnings)
   # must be herein, as most subroutines are already defined in main
   # warnings pragma is local to this file!
no warnings 'once';     ## no critic qw(TestingAndDebugging::ProhibitNoWarnings)
   # "... used only once: possible typo ..." appears when called as main only

#_____________________________________________________________________________
#___________________________________________________ package initialisation __|

my  $SID_trace      = "@(#) OTrace.pm 3.29 24/05/28 11:22:20";
our $VERSION        = "24.01.24";

# public package variables
our $trace          = 0;
our $verbose        = 0;
our $prefix_trace   = "#". __PACKAGE__ . ":";
our $prefix_verbose = "#". __PACKAGE__ . ":";

use Exporter qw(import);

BEGIN { # mainly required for testing ...
    # SEE Perl:@INC
    # SEE Perl:BEGIN perlcritic
    my $_path = $0;     $_path =~ s#[/\\][^/\\]*$##x;
    if (exists $ENV{'PWD'} and not (grep{/^$ENV{'PWD'}$/} @INC) ) {
        unshift(@INC, $ENV{'PWD'});
    }
    unshift(@INC, $_path)   if not (grep{/^$_path$/} @INC);
    unshift(@INC, "lib")    if not (grep{/^lib$/}    @INC);
    if (not exists &_is_cfg_intern) {
        sub _is_member      { my ($is,$ref)=@_; return grep({lc($is) eq lc($_)} @{$ref}); }
        sub _is_cfg_intern  { return _is_member(shift, \@{$cfg{'commands_int'}});}
    }
    our @EXPORT_OK = qw(
        trace_
        trace
        trace0
        trace1
        trace2
        trace3
        time_get
        arg_show
        args_show
        init_show
        exit_show
        ciphers_show
        target_show
        test_show
        done
    );
}

#-------------------------------------------------------------------------
# Version < 24.01.24
#o-saft.pl::Net::SSLinfo
#SSLinfo::do_ssl_open(localhost,443,,) {
#SSLinfo::do_ssl_open cipherlist: ALL:NULL:eNULL:aNULL:LOW:EXP
#SSLinfo::do_ssl_open ::use_http: 1             <== inkonsistent
#SSLinfo::do_ssl_open: request localhost:443    <== inkonsistent
# ...
#o-saft.pl::checkdates(localhost, 443) {
#o-saft.pl:: valid-years = 0                            <== inkonsistent
#o-saft.pl::checkdates() }
# ...
#o-saft.pl::check_nextproto: type=ALPN, np=http/1.1     <== inkonsistent
# ...
#o-saft.pl:: do=certversion cn ...                      <== inkonsistent
#o-saft.pl::printdata(simple, localhost, 443) {

# --trace-ARG
#yeast.pl:  ARG: option=  --tracearg

# --trace-CMD  oder --trace-TIME
#yeast.pl 01:00:01 CMD: mod{
#yeast.pl 01:00:01 CMD: mod}
#-------------------------------------------------------------------------

# Version >= 24.01.24
#o-saft.pl 01:00:01 SSLeay
#o-saft.pl 01:00:01 SSLinfo::do_ssl_open(localhost,443,,) {
#o-saft.pl 01:00:01  do=certversion cn ...
#o-saft.pl 01:00:01 printdata(simple, localhost, 443) {
#-------------------------------------------------------------------------

use Data::Dumper qw(Dumper);
use OText        qw(%STR);
use OCfg;   # sets %cfg
# TODO: 01jan24: must use %::cmd, %::data, %::checks instead of %data; reason unknown

#_____________________________________________________________________________
#__________________________________________________________________ methods __|

sub time_get    {
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
} # time_get

#sub __trace     { my @txt = @_; return sprintf("#%s%s %s", $cfg{'prefix_trace'}, time_get(), "@txt"); }
sub __trace     { my @txt = @_; return sprintf("%s%s %s", $prefix_trace, time_get(), "@txt"); }
sub trace_      { my @txt = @_; printf("%s"  , "@txt")           if (0 < $cfg{'trace'}); return; }
sub trace       { my @txt = @_; printf("%s\n", __trace($txt[0])) if (0 < $cfg{'trace'}); return; }
sub trace0      { my @txt = @_; printf("%s\n", __trace(""))      if (0 < $cfg{'trace'}); return; }
sub trace1      { my @txt = @_; printf("%s\n", __trace(@txt))    if (1 < $cfg{'trace'}); return; }
sub trace2      { my @txt = @_; printf("%s\n", __trace(@txt))    if (2 < $cfg{'trace'}); return; }
sub trace3      { my @txt = @_; printf("%s\n", __trace(@txt))    if (3 < $cfg{'trace'}); return; }
# if --trace-arg given
sub arg_show    { my @txt = @_; printf("%s\n", __trace(" ARG: ", @txt)) if $cfg{'out'}->{'traceARG'}; return; }

# more methods see below: public test methods

#_____________________________________________________________________________
#_________________________________________________________ internal methods __|

sub __LINE      { return "#----------------------------------------------------"; }
sub __undef     { my $v = shift; $v = $STR{'UNDEF'} if not defined $v; return $v; }
    # empty string should not return $STR{'UNDEF'}
sub ___ARR      { return join(" ", "[", sort(@_), "]"); }
sub _q_ARR      { return ___ARR(map{"`".$_."'"} @_); }
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
                        $data .= __TEXT("# - - - - HASH: $key= {\n");
                        foreach my $k (sort keys %{$ref->{$key}}) {
                            my $val = "";
                            if (defined ${$ref->{$key}}{$k}) {
                               if ('ARRAY' eq ref(${$ref->{$key}}{$k})) {
                                   $val = ___ARR(@{$ref->{$key}{$k}});
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
sub __data_head { return __data_title("key", "command", " %data ", "%checks", "cmd-ch.", " short ", "intern ", ""); }
sub __data_line { return sprintf("=%19s+%s+%s+%s+%s+%s+%s+%s", "-"x19, "-"x7, "-"x7, "-"x7, "-"x7, "-"x7, "-"x7, "-"x7); }
sub __data_data { return sprintf("%20s\t%s\t%s\t%s\t%s\t%s\t%s\t%s", @_); }

# subs for formatted maps
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

sub _test_help  {
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
    #       doc/help.txt
    return $data;
} # _test_help

sub _test_avail {
    local $\ = "\n";
    printf("#%s:\n", (caller(0))[3]);
    print <<'EoT';

=== internal data structures: overview of commands, %data and %checks ===
=
= Print a simple overview of all available commands for  +info  and  +check .
= The purpose is to show if a proper key is defined in  %data and %checks  for
= each command from  %cfg{'commands'}  and vice versa.
=
=   column      description
=  ------------+--------------------------------------------------
=   key         key in %cfg{'commands'}
=   command     key (see above) available as command: +key
=   %data       command returns %data  (part of +info)
=   %checks     command returns %check (part of +check)
=   cmd-ch.     command listed in ...
=   short       description of command available as short text
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
} # _test_avail

sub _test_init  {
    local $\ = "\n";
    local $Data::Dumper::Deparse=1; # parse code, see man Data::Dumper
    my $line = "#--------------------+-------------------------------------------";
    printf("#%s:\n", (caller(0))[3]);
    print <<'EoT';

=== internal data structures: initialisation of %cfg, %data and %checks ===
=
= Print initialised data structures  %data and %checks  after all command-line
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
    foreach my $key (sort keys %::data) { # ugly and slow code
        my $code = Dumper($::data{$key}->{val});
        # use Dumper() to get code, returns something like example 1:
        #     $VAR1 = sub {
        #                 package Data;
        #                 use warnings;
        #                 use strict;
        #                 SSLinfo::version($_[0], $_[1]);
        #             };
        # or example 2:
        #     $VAR1 = sub {
        #         'txt' => 'Target default DTLS 0.9 cipher',
        #         'val' => sub {
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
} # _test_init

sub _test_maps  {
    printf("#%s:\n", (caller(0))[3]);
    print <<'EoT';

=== internal data structures: %cfg{openssl}, %cfg{ssleay} ===
=
= Print internal mappings for openssl functionality (mainly options).
=
EoT
    local $\ = "\n";
    my $data = SSLinfo::test_sslmap();
       $data =~ s/^#/#$cfg{'me'}: #/smg;
    print $data;
    _pline("%cfg{openssl_option_map} {");
    print __prot_option();
    _pline("%cfg{openssl_version_map} {");
    print __prot_version();
    return;
} # _test_maps

sub _test_prot  {
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
} # _test_prot

sub _test_regex {
    #? print content of %cfg{regex}
    printf("#%s:\n", (caller(0))[3]);
    print <<'EoT';

=== internal data structure %cfg{regex} ===
=
= Print information internal data structure %cfg{regex}.
=
EoT
    local $\ = "\n";
    _pline("%cfg{regex} {");
    foreach my $key (sort keys %{$cfg{'regex'}}) {
	_p_k_v($key, $cfg{'regex'}->{$key});
    }
    _pline("%cfg{regex} }");
    return;
} # _test_regex

sub _test_methods {
    printf("#%s:\n", (caller(0))[3]);
    print <<'EoT';

=== internal list of methods to call openssl ===
=
= Print available methods in Net::SSLeay.
=
EoT
    my $list = SSLinfo::test_methods();
       $list =~ s/ /\n  /g;
    print "  $list\n";
    return;
} # _test_methods

sub _test_openssl {
    printf("#%s:\n", (caller(0))[3]);
    print <<'EoT';

=== internal data structure %_OpenSSL_opt ===
=
= Print internal data structure from SSLinfo.
=
EoT
    my $list = SSLinfo::test_openssl();
       #$list =~ s/ /\n# /g;
    print "$list\n";
    return;
} # _test_openssl

sub _test_sclient {
    printf("#%s:\n", (caller(0))[3]);
    print <<'EoT';

=== internal list of openssl s_client options ===
=
= Print available options for 'openssl s_client' from Net::SSLeay.
=
EoT
    my $list = SSLinfo::test_sclient();
       $list =~ s/ /\n  /g;
    print "  $list\n";
    return;
} # _test_sclient

sub _test_sslmap  {
    printf("#%s:\n", (caller(0))[3]);
    print <<'EoT';

=== internal list of constants for SSL protocols ===
=
= Print available constants for SSL protocols in Net::SSLeay.
=
EoT
    print SSLinfo::test_sslmap() . "\n";
    return;
} # _test_sslmap

sub _test_ssleay  {
    printf("#%s:\n", (caller(0))[3]);
    print <<'EoT';
 
=== internal data of Net::SSLeay ===
=
= Print information about Net::SSLeay capabilities.
=
EoT
    print SSLinfo::test_ssleay();
    return;
} # _test_ssleay

sub _test_memory  {
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
= Print memory usage of internal variables.
=
EoT
    my $line  = "=------+----------------";
    print "= Bytes variable\n$line";
    foreach my $k (sort keys %cfg) {
        printf("%6s\t%s\n", Devel::Size::total_size(\$cfg{$k}),    "%cfg{$k}");
    }
    foreach my $k (sort keys %::checks) {
        printf("%6s\t%s\n", Devel::Size::total_size(\$checks{$k}), "%checks{$k}");
    }
    foreach my $k (sort keys %dbx) {
        printf("%6s\t%s\n", Devel::Size::total_size(\$dbx{$k}),    "%dbx{$k}");
    }
    #foreach my $k (sort keys %ciphers) {    # useless, as each entry is about 2k
    #    printf("%6s\t%s\n", Devel::Size::total_size(\$ciphers{$k}), "%ciphers{$k}");
    #}
    #foreach my $k (sort keys %data) {       # most entries report 42k, which is wrong
    #    printf("%6s\t%s\n", Devel::Size::total_size(\$data{$k}), "%data{$k}");
    #}
    print "$line\n";
    my $bytes = 0;
    # get all global variables and grep for our ones
    # ugly code, but generic
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
        printf("%7s\t%s\n", $size, "%$v");
    }
    print "$line\n";
    printf("%7s\t(%2.2f MB) total\n", $bytes, $bytes/1024/1024);
    # the traditional way ...
    #print "%cfg    : ", Devel::Size::total_size(\%cfg);
    #print "%data   : ", Devel::Size::total_size(\%data);
    #print "%checks : ", Devel::Size::total_size(\%checks);
    #print "%ciphers: ", Devel::Size::total_size(\%ciphers);
    #print "\@results: ", Devel::Size::total_size(\@cipher_results);
    #print "%text   : ", Devel::Size::total_size(\%text);
    #print "%_SSLinfo   : ", Devel::Size::total_size(\%SSLinfo::_SSLinfo);
    return;
} # _test_memory

sub __dump_var  {
    #? print varable name and it's content using Data::Dumper()
    #  unfortunately Data::Dumper is not able to print the name of the variable
    #  hence this cumbersome approach (see settings in calling function)
    my $type = shift;
    my $var  = shift;
    my $name = "$type$var";
    _pline("$name {");
    ## no critic qw(References::ProhibitDoubleSigils)   # see NOTE: 01jan24
    $var = $::{$var};
    printf("%s = %s\n", $name, Dumper($$var))  if ('$' eq $type);
    printf("%s = %s\n", $name, Dumper(\%$var)) if ('%' eq $type);
    printf("%s = %s\n", $name, Dumper(\@$var)) if ('@' eq $type);
    ## use critic
    _pline("$name }");
    return;
} # __dump_var

sub _test_vars  {
    printf("#%s:\n", (caller(0))[3]);
    local $\ = "\n";
    # for details on used $Data::Dumper:: varaibles, see man Data::Dumper
    local $Data::Dumper::Deparse    = 1;# we want the code references
        # TODO: use Deparse=1 and filter code, see _test_init()
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

=== internal data structures: %ciphers %prot %cfg %data %info %checks ===
=
= Print initialised internal data structures using Perl's Data::Dumper.
=
EoT
    __dump_var('$', 'cipher_results');
    __dump_var('%', 'ciphers');
    __dump_var('%', 'ciphers_desc');
    __dump_var('%', 'prot');
    __dump_var('%', 'cfg');
    __dump_var('%', 'data');
    __dump_var('%', 'info');
    __dump_var('%', 'checks');
    return;
} # _test_vars

#_____________________________________________________________________________
#______________________________________________________ public test methods __|

sub ciphers_show {
    #? print ciphers fromc %cfg (output optimised for +cipher)
    return if (0 >= $cfg{'trace'});
    my $need = shift;
    _pline("ciphers {");
    my $_cnt = scalar @{$cfg{'ciphers'}};
    my $ciphers = "@{$cfg{'ciphers'}}"; # not yet used
    _p_k_v("_need_cipher", $need);
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
            @range = OCfg::get_ciphers_range('TLSv13', $cfg{'cipherrange'});
               # NOTE: OCfg::get_ciphers_range() first arg is the SSL version,
               #       which is usually unknown here, hence TLSv13 is passed
            $_cnt = scalar @range;
        }
        $_cnt = sprintf("%5s", $_cnt);  # format count
        _p_k_v("cmd{extciphers}", $::cmd{'extciphers'} . " (1=use cipher from openssl)");
        foreach my $key (qw(starttls ciphermode cipherpattern cipherrange)) {
            _p_k_v($key,    $cfg{$key});
        }
        # format range text
        foreach my $txt (split(/\n/, $cfg{'cipherranges'}->{$cfg{'cipherrange'}})) {
            next if $txt =~ m/^\s*$/;
            $txt =~ s/^\s*/                /;
            _ptext($txt);
        }
        _p_k_v("$_cnt ciphers", "@range");
        _p_k_v("cipher_dh",     $cfg{'cipher_dh'});
        _p_k_v("cipher_md5",    $cfg{'cipher_md5'});
        _p_k_v("cipher_ecdh",   $cfg{'cipher_ecdh'});
        _p_k_v("cipher_npns",   ___ARR(@{$cfg{'cipher_npns'}}));
        _p_k_v("cipher_alpns",  ___ARR(@{$cfg{'cipher_alpns'}}));
    }
    _pline("ciphers }");
    return;
} # ciphers_show

sub target_show {
    #? print information about targets to be processed
    # full list if 1<trace
    my @targets = @_;
    return if (0 >= $cfg{'trace'});
    #print " === print internal data structures for a targets === ";
    my $data = "";
    if (2 > $cfg{'trace'}) { # simple list
        foreach my $target (@targets) {
            next if (0 == @{$target}[0]);       # first entry with default settings
            $data .= sprintf("%s:%s%s ", @{$target}[2..3,6]);
               # the perlish way instead of get_target_{host,port,path}
        }
        _p_k_v("targets", "[ $data]");
    } else {
        $data  = "# - - - -ARRAY: targets= [\n";
        $data .= __TEXT(sprintf(" #  Index %6s %24s : %5s %10s %5s %-16s %s\n",
                "Prot.", "Hostname or IP", "Port", "Auth", "Proxy", "Path", "Orig. Parameter"));
        foreach my $target (@targets) {
            # first entry with default settings printed also
            $data .= __TEXT(sprintf("    [%3s] %6s %24s : %5s %10s %5s %-16s %s\n", @{$target}[0,1..7]));
        }
        $data .= __TEXT("# - - - -ARRAY: targets ]\n");
        _ptext($data);
    }
    return;
} # target_show

sub init_show   {   ## no critic qw(Subroutines::ProhibitExcessComplexity)
    #? print important content of %cfg and %cmd hashes
    #? more output if 1<trace; full output if 2<trace
    return if (0 >= $cfg{'trace'});
    local $\ = "\n";
    my $arg = " (does not exist)";
    if (-f $cfg{'RC-FILE'}) { $arg = " (exists)"; }
    _ptext("!!Hint: use --trace=2  to see SSLinfo variables")   if (2 > $cfg{'trace'});
    _ptext("!!Hint: use --trace=2  to see external commands")   if (2 > $cfg{'trace'});
    _ptext("!!Hint: use --trace=3  to see full %cfg")           if (3 > $cfg{'trace'});
    _pnull();
    _ptext("#") if (3 > $cfg{'trace'});
    _pline("");
    #_p_k_v("init_show::SID", $SID_trace) if (2 < $cfg{'trace'}); # 24.01.24 removed
    _p_k_v("$0", main::_VERSION()); ## no critic qw(Subroutines::ProtectPrivateSubs)
        # TBD: $0 is same as $ARG0 but wrong when called as standalone
    # official VERSIONs, not those of the current files !
    _p_k_v("OCfg",      __undef($OCfg::VERSION));
    _p_k_v("SSLhello",  __undef($SSLhello::VERSION));
    _p_k_v("SSLinfo",   __undef($SSLinfo::VERSION));
    # quick info first
    _p_k_v("RC-FILE",   $cfg{'RC-FILE'} . $arg);
    _p_k_v("--rc",      ((grep{/(?:--rc)$/i}     @ARGV) > 0)? 1 : 0);
    _p_k_v("--no-rc",   ((grep{/(?:--no.?rc)$/i} @ARGV) > 0)? 1 : 0);
    _p_k_v("verbose",   $cfg{'verbose'});
    _p_k_v("trace",    "$cfg{'trace'}, traceARG=$cfg{'out'}->{'traceARG'}, traceKEY=$cfg{'out'}->{'traceKEY'}, traceTIME=$cfg{'out'}->{'traceTIME'}");
    _p_k_v("time_absolut", $cfg{'out'}->{'time_absolut'});
    _p_k_v("dbx{files}", ___ARR(@{$dbx{'files'}}));

    if (1 < $cfg{'trace'}) {
        _pline("SSLinfo {");
        _p_k_v("::trace",         $SSLinfo::trace);
        _p_k_v("::linux_debug",   $SSLinfo::linux_debug);
        _p_k_v("::slowly",        $SSLinfo::slowly);
        _p_k_v("::timeout",       $SSLinfo::timeout);
        _p_k_v("::use_openssl",   $SSLinfo::use_openssl);
        _p_k_v("::use_sclient",   $SSLinfo::use_sclient);
        _p_k_v("::use_extdebug",  $SSLinfo::use_extdebug);
        _p_k_v("::use_nextprot",  $SSLinfo::use_nextprot);
        _p_k_v("::use_reconnect", $SSLinfo::use_reconnect);
        _p_k_v("::use_SNI",       $SSLinfo::use_SNI);
        _p_k_v("::use_http",      $SSLinfo::use_http);
        _p_k_v("::no_cert",       $SSLinfo::no_cert);
        _p_k_v("::no_cert_txt",   $SSLinfo::no_cert_txt);
        _p_k_v("::protos_alpn",   $SSLinfo::protos_alpn);
        _p_k_v("::protos_npn",    $SSLinfo::protos_npn);
        _p_k_v("::sclient_opt",   $SSLinfo::sclient_opt);
        _p_k_v("::ignore_case",   $SSLinfo::ignore_case);
        _p_k_v("::timeout_sec",   $SSLinfo::timeout_sec);
        _pline("SSLinfo }");
    }

    _pline("%cmd {");
    if (2 > $cfg{'trace'}) {    # user-friendly information
        _p_k_v("path",      ___ARR(@{$::cmd{'path'}}));
        _p_k_v("libs",      ___ARR(@{$::cmd{'libs'}}));
        _p_k_v("envlibvar", $::cmd{'envlibvar'});
        _p_k_v("timeout",   $::cmd{'timeout'});
        _p_k_v("openssl",   $::cmd{'openssl'});
    } else {    # full information
        foreach my $key (sort keys %::cmd) { _ptype(\%::cmd, $key); }
    }
    _p_k_v("extopenssl",    $::cmd{'extopenssl'} . " (1= use openssl to check ciphers)");
    _p_k_v("extciphers",    $::cmd{'extciphers'} . " (1= use cipher from openssl)");
    _pline("%cmd }");

    if (1 < $cfg{'trace'}) {    # full information
        _pline("complete %cfg {");
        foreach my $key (sort keys %cfg) {
            if ($key =~ m/(hints|openssl|ssleay|sslerror|sslhello|regex|^out|^use)$/) { # |data
                # TODO: ugly data structures ... should be done by _p_k_v()
                _ptext("# - - - - HASH: $key= {");
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
                    target_show(@{$cfg{'targets'}});
                } else {
                    if ("time0" eq $key and defined $ENV{'OSAFT_MAKE'}) {
                        # SEE Make:OSAFT_MAKE (in Makefile.pod)
                        my $t0 = $cfg{'time0'};
                        $cfg{'time0'} = $STR{MAKEVAL};
                        _ptype(\%cfg, $key);
                        $cfg{'time0'} = $t0;
                    } else {
                        if ("RC-ARGV" eq $key) {
                            # dirty hack because values may contain whitespace
                            print(___K_V($key, _q_ARR(@{$cfg{'RC-ARGV'}})));
                        } else {
                            _ptype(\%cfg, $key);
                        }
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
    foreach my $key (qw(ca_depth ca_path ca_file)) {
        _p_k_v($key, $cfg{$key});
    }
    _p_k_v("default port", "$port (last specified)");
    target_show(@{$cfg{'targets'}});
    _ptext("              use_SNI=", $SSLinfo::use_SNI . ", force-sni=$cfg{'use'}->{'forcesni'}, sni_name=$sni_name");
        # _ptext() because of multiple values; concatenation with . to avoid spaces
    _p_k_v("use->http",     $cfg{'use'}->{'http'});
    _p_k_v("use->https",    $cfg{'use'}->{'https'});
    _p_k_v("out->hostname", $cfg{'out'}->{'hostname'});
    _p_k_v("out->header",   $cfg{'out'}->{'header'});
    foreach my $key (qw(format legacy cipherrange slow_server_delay starttls starttls_delay)) {
        _p_k_v($key,        $cfg{$key});
    }
    foreach my $key (qw(starttls_phase starttls_error cipher)) {
        _p_k_v($key,        ___ARR(@{$cfg{$key}}));
    }
    _p_k_v("SSL version",   ___ARR(@{$cfg{'version'}}));
    _p_k_v("SSL versions",  ___ARR(map{$_."=".$cfg{$_}} sort(@{$cfg{versions}})));
    _p_k_v("special SSLv2", "null-sslv2=$cfg{'use'}->{'nullssl2'}, ssl-lazy=$cfg{'use'}->{'ssl_lazy'}");
    _p_k_v("ignore output", ___ARR(@{$cfg{'ignore-out'}}));
    _p_k_v("user commands", ___ARR(@{$cfg{'commands_usr'}}));
    _p_k_v("given commands", ___ARR(@{$cfg{'done'}->{'arg_cmds'}}));
    _p_k_v("commands",      ___ARR(@{$cfg{'do'}}));
    _pline("user-friendly cfg }");
    _ptext("(more information with: --trace=2  or  --trace=3 )") if (1 > $cfg{'trace'});
    # $cfg{'ciphers'} may not yet set, print with OTrace::ciphers_show()
    return;
} # init_show

sub exit_show   {
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
} # exit_show

sub args_show   {
    #? print information about command-line arguments
    # using arg_show() may be a performance penulty, but it's trace anyway ...
    return if (0 >= $cfg{'out'}->{'traceARG'});
    _pline("ARGV {");
    arg_show("# summary of all arguments and options from command-line");
    arg_show("       called program ARG0= " . $cfg{'ARG0'});
    arg_show("     passed arguments ARGV= " . ___ARR(@{$cfg{'ARGV'}}));
    arg_show("                   RC-FILE= " . $cfg{'RC-FILE'});
    arg_show("      from RC-FILE RC-ARGV= ($#{$cfg{'RC-ARGV'}} more args ...)");
    if (2 > $cfg{'trace'}) {
    arg_show("      !!Hint:  use --trace=2 to get the list of all RC-ARGV");
    arg_show("      !!Hint:  use --trace=3 to see the processed RC-ARGV");
                  # NOTE: ($cfg{'trace'} does not work here
    }
    arg_show("      from RC-FILE RC-ARGV= " . _q_ARR(@{$cfg{'RC-ARGV'}})) if (1 < $cfg{'trace'});
    my $txt = "[ ";
    foreach my $target (@{$cfg{'targets'}}) {
        next if (0 == @{$target}[0]);   # first entry conatins default settings
        $txt .= sprintf("%s:%s ", @{$target}[2..3]); # the perlish way
    }
    $txt .= "]";
    arg_show("         collected targets= " . $txt);
    if (2 < $cfg{'trace'}) {
    arg_show(" #--v { processed files, arguments and options");
    arg_show("    read files and modules= ". ___ARR(@{$dbx{file}}));
    arg_show("processed  exec  arguments= ". ___ARR(@{$dbx{exe}}));
    arg_show("processed normal arguments= ". ___ARR(@{$dbx{argv}}));
    arg_show("processed config arguments= ". _q_ARR(@{$dbx{cfg}}));
    arg_show(" #--v }");
    }
    _pline("ARGV }");
    return;
} # args_show

sub rcfile_show {
    #? print content read from RC-FILE ## NOT YET USED ##
    return if (0 >= $cfg{'trace'});
    _pline("RC-FILE {");
    _pline("RC-FILE }");
    return;
} # rcfile_show {

sub test_show   {
    #? dispatcher for internal tests, initiated with option --test-*
    #  cannot be called using __FILE__ itself
    my $arg = shift;    # normalised option, like --testinit, --testcipherlist
    _ptext($arg);
    if ($arg =~ /^--test.?ciphers?.?list$/) {   # allow not normalised also
        # --test-ciphers-list is for printing ciphers in common --v format, it
        # also honors the option  --cipherrange=  additonaly it relies on some
        # special settings in $cfg{};  +cipher  must be added to $cfg{'do'} to
        # enforce printing, also at least one TLS version must be used;
        # changing the configuration here should  not harm other functionality
        # changing the $cfg{} here should not harm other functionality because
        # test_show() is for debugging only and will exit then
        push(@{$cfg{'do'}}, 'cipher'); # enforce printing cipher informations
        push(@{$cfg{'version'}}, 'TLSv1') if (0 > $#{$cfg{'version'}});
        $cfg{'trace'} = 1;
        ciphers_show(1); # simulate _need_cipher()
        return;
    }
    OCfg::test_cipher_regex()   if ($arg =~ m/cipher.?regex/);
    Ciphers::show($arg)         if ($arg =~ /^--test.?cipher/);
    _test_help()        if ('--test'          eq $arg);
    _test_help()        if ('--tests'         eq $arg);
    _test_help()        if ('--testtest'      eq $arg);
    _test_sclient()     if ('--testsclient'   eq $arg); # SSLinfo
    _test_ssleay()      if ('--testssleay'    eq $arg); # SSLinfo
    _test_sslmap()      if ('--testsslmap'    eq $arg); # SSLinfo
    _test_openssl()     if ('--testopenssl'   eq $arg); # SSLinfo
    _test_methods()     if ('--testmethods'   eq $arg); # SSLinfo
    _test_memory()      if ('--testmemory'    eq $arg);
    _test_regex()       if ('--testregex'     eq $arg); # %cfg{regex}
    $arg =~ s/^[+-]-?tests?[._-]?//; # remove --test
    _test_avail()       if ($arg =~ m/^avail(?:able)?$/);
    _test_init()        if ('init'            eq $arg);
    _test_maps()        if ('maps'            eq $arg);
    _test_prot()        if ('prot'            eq $arg);
    _test_vars()        if ('vars'            eq $arg);
    return;
} # test_show

#_____________________________________________________________________________
#_____________________________________________________________________ main __|

sub _main       {
    my $arg = shift || "--help";    # without argument print own help
    $cfg{'time0'} = $STR{MAKEVAL} if (defined $ENV{'OSAFT_MAKE'});
        # SEE Make:OSAFT_MAKE (in Makefile.pod)
        # dirty hack here which asumes that _main() is called to print
        # information only and does not need time0
    #  SEE Perl:binmode()
    binmode(STDOUT, ":unix:utf8"); ## no critic qw(InputOutput::RequireEncodingWithUTF8Layer)
    binmode(STDERR, ":unix:utf8"); ## no critic qw(InputOutput::RequireEncodingWithUTF8Layer)
    my %usage = (
      '# commands to print data' => {'--test-regex'=>'show %cfg{regex}'},
    );
    if ($arg =~ m/--?h(elp)?$/x)        { OText::print_pod($0, __FILE__, $SID_trace); exit 0; }
    if ($arg =~ m/--usage?$/)           { OText::usage_show("", \%usage); exit 0; }
    # else
    # ----------------------------- commands
    if ($arg =~ m/^--?trace/)           { $trace++; }
    if ($arg eq 'version')              { print "$SID_trace\n"; exit 0; }
    if ($arg =~ m/^[-+]?V(ERSION)?$/)   { print "$VERSION\n";   exit 0; }
    if ($arg =~ m/--test.?regex$/)      { _test_regex();        exit 0; }
    if ($arg =~ m/--tests?$/)           { _test_help();         exit 0; }
    if ($arg =~ m/--test[_.-]?(.*)/)    {
        $arg = "--test-$2";
        printf("#$0: direct testing not yet possible, please try:\n   o-saft.pl $arg\n");
    }
    exit 0;
} # _main

sub done  {};   # dummy to check successful include

#_____________________________________________________________________________
#_____________________________________________________ public documentation __|

=pod

=encoding utf8

=head1 NAME

OTrace.pm - Perl module for tracing o-saft.pl


=head1 SYNOPSIS

=over 2

=item require "OTrace.pm";  # from within Perl code

=item use OTrace;           # from within Perl code

=item OTrace.pm <L<OPTIONS|OPTIONS>>  # on command-line

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
For example  I<--test-maps>  calls  C<_test_maps()>.

=head3 _test_help( )

=head3 _test_avail( )

=head3 _test_init( )

=head3 _test_maps( )

=head3 _test_prot( )

=head3 _test_vars( )

=head3 _test_methods( )

=head3 _test_openssl( )

=head3 _test_sclient( )

=head3 _test_sslmap( )

=head3 _test_ssleay( )

=head3 _test_memory( )

=head2 Public functions

Hint: if functions are not used in the calling program, they should be defined
as empty stub there, for example:

    sub init_show() {}

=head3 OTrace::ciphers_show( )

=head3 OTrace::target_show( )

=head3 OTrace::rcfile_show( )

=head3 OTrace::arg_show( )

=head3 OTrace::args_show( )

=head3 OTrace::init_show( )

=head3 OTrace::exit_show( )

=head3 OTrace::trace( )

=head3 OTrace::trace2( )

=head3 OTrace::trace3( )

=head3 OTrace::trace4( )

=head3 OTrace::test_show( )

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
here. In that case simply call the function in C<init_show> or C<exit_show>
they are called at beginning and end of L<o-saft.pl|o-saft.pl>.
It's just important that  L<o-saft.pl|o-saft.pl>  was called with either the
I<--v> or any I<--trace*>  option, which then loads this file automatically.


=head1 VERSION

3.29 2024/05/28

=head1 AUTHOR

23-nov-23 Achim Hoffmann

=cut

## PACKAGE }

#_____________________________________________________________________________
#_____________________________________________________________________ self __|

_main(@ARGV) if (not defined caller);

1;
