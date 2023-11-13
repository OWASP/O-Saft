#!/usr/bin/perl
## PACKAGE {

#!# Copyright (c) 2023, Achim Hoffmann
#!# This  software is licensed under GPLv2. Please see o-saft.pl for details.

package main;   # ensure that main:: variables are used, if not defined herein

# HACKER's INFO
#       Following (internal) functions from o-saft.pl are used:
#       _is_cfg_do()
#       _is_cfg_intern()
#       _is_member()
#       _need_cipher()

## no critic qw(Subroutines::RequireArgUnpacking)
#        Parameters are ok for trace output.

## no critic qw(Subroutines::ProhibitUnusedPrivateSubroutines)
#        That's intended.

## no critic qw(ValuesAndExpressions::ProhibitImplicitNewlines)
#        That's intended in strings; perlcritic is too pedantic.

## no critic qw(RegularExpressions::RequireExtendedFormatting)
#        We believe that most RegEx are not too complex.

# for Severity 2 only:
## no critic qw(ValuesAndExpressions::ProhibitMagicNumbers)
#        We have some constants herein, that's ok.

## no critic qw(ValuesAndExpressions::ProhibitNoisyQuotes)
#        We have a lot of single character strings, herein, that's ok.

## no critic qw(TestingAndDebugging::RequireUseStrict)
#  `use strict;' not useful here, as we mainly use our global variables
use warnings;

no warnings 'redefine'; ## no critic qw(TestingAndDebugging::ProhibitNoWarnings)
   # must be herein, as most subroutines are already defined in main
   # warnings pragma is local to this file!
no warnings 'once';     ## no critic qw(TestingAndDebugging::ProhibitNoWarnings)
   # "... used only once: possible typo ..." appears when called as main only

BEGIN { # mainly required for testing ...
    # SEE Perl:@INC
    # SEE Perl:BEGIN perlcritic
    my $_me   = $0;     $_me   =~ s#.*[/\\]##x;
    my $_path = $0;     $_path =~ s#[/\\][^/\\]*$##x;
    unshift(@INC, $_path)   if (1 > (grep{/^$_path$/} @INC));
    unshift(@INC, "..")     if (1 > (grep{/^\.\.$/}   @INC));
    unshift(@INC, ".")      if (1 > (grep{/^\.$/}     @INC));
}

use OSaft::Text qw(%STR print_pod);
use osaft;

my  $SID_dbx= "@(#) o-saft-dbx.pm 2.29 23/11/13 12:24:36";

#_____________________________________________________________________________
#__________________________________________________________________ methods __|
# debug methods

sub _yTIME      {
    return "" if (not _is_cfg_out('traceTIME'));
    my $now = time() - ($time0 || 0);
       $now = time() if (_is_cfg_out('time_absolut'));# $time0 defined in main
       $now +=1 if (0 > $now);  # fix runtime error: $now == -1
    return sprintf(" %02s:%02s:%02s", (localtime($now))[2,1,0]);
}
sub __undef     { my $v = shift; $v = $STR{'UNDEF'} if not defined $v; return $v; }
sub __yeast     { return $cfg{'prefix_verbose'} . $_[0]; }
sub ___ARG      { return $cfg{'prefix_verbose'} .            " ARG: " . join(" ", @_);    }
sub ___CMD      { return $cfg{'prefix_verbose'} . _yTIME() . " CMD: " . join(" ", @_);    }
sub __line      { return "#----------------------------------------------------" . $_[0]; }
sub ___ARR      { return join(" ", "[", sort(@_), "]"); }
sub __INIT      { my ($k, $v) = @_; $v = __undef($v); return sprintf("%s%21s= %s", $cfg{'prefix_verbose'}, $k, $v );    }
sub __TRAC      { my ($k, $v) = @_; $v = __undef($v); return sprintf("%s%14s= %s", $cfg{'prefix_verbose'}, $k, $v );    }
sub _y_ARG      { local $\ = "\n"; print ___ARG(@_) if (_is_cfg_out('traceARG')); return; }
sub _y_CMD      { local $\ = "\n"; print ___CMD(@_) if (_is_cfg_out('traceCMD')); return; }
sub _yeast      { local $\ = "\n"; print __yeast($_[0]);return; }
sub _yINIT      { local $\ = "\n"; print __INIT(@_);    return; }
sub _yTRAC      { local $\ = "\n"; print __TRAC(@_);    return; }
sub _yline      { _yeast(__line($_[0]));                return; }
sub _ynull      { _yeast("value $STR{'UNDEF'} means that internal variable is not defined @_"); return; }
sub __trac      {}      # forward declaration
sub __trac      {
    #? print variable according its type, understands: CODE, SCALAR, ARRAY, HASH
    my $ref  = shift;   # must be a hash reference
    my $key  = shift;
    my $data = "";
    if (not defined $ref->{$key}) {
        # undef is special, avoid perl warnings
        return __TRAC($key, "$STR{'UNDEF'}");
    }
    SWITCH: for (ref($ref->{$key})) {   # ugly but save use of $_ here
        /^$/    && do { $data .= __TRAC($key, $ref->{$key}); last SWITCH; };
        /CODE/  && do { $data .= __TRAC($key, "<<code>>");   last SWITCH; };
        /SCALAR/&& do { $data .= __TRAC($key, $ref->{$key}); last SWITCH; };
        /ARRAY/ && do { $data .= __TRAC($key, ___ARR(@{$ref->{$key}})); last SWITCH; };
        /HASH/  && do { last SWITCH if (2 >= $ref->{'trace'});      # print hashes for full trace only
                        $data .= __yeast("# - - - - HASH: $key = {");
                        foreach my $k (sort keys %{$ref->{$key}}) {
                            $data .= __TRAC("    ".$key."->".$k, join("-", ${$ref->{$key}}{$k})); # TODO: output needs to be improved
                        };
                        $data .= __yeast("# - - - - HASH: $key }");
                        last SWITCH;
                      };
        # DEFAULT
                        $data .= __yeast($STR{WARN} . " user defined type '$_' skipped");
    } # SWITCH

    return $data;
} # __trac

sub _yeast_trac { local $\ = "\n"; my $d = __trac(@_); print $d if ($d !~ m/^\s*$/); return; }
    #? print variable according its type, understands: CODE, SCALAR, ARRAY, HASH
    #  avoids printing of empty lines

sub _yeast_ciphers_list {
    #? print ciphers fromc %cfg (output optimised for +cipher)
    return if (0 >= ($cfg{'trace'} + $cfg{'verbose'}));
    _yline(" ciphers {");
    my $_cnt = scalar @{$cfg{'ciphers'}};
    my $need = _need_cipher();
    my $ciphers = "@{$cfg{'ciphers'}}"; # not yet used
    _yeast("  _need_cipher= $need");
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
        _yeast("use cipher from openssl= " . $cmd{'extciphers'});
        _yeast("      starttls= " . $cfg{'starttls'});
        _yeast(" cipherpattern= " . $cfg{'cipherpattern'});
        _yeast("   cipherrange= " . $cfg{'cipherrange'});
        # format range text
        foreach my $txt (split(/\n/, $cfg{'cipherranges'}->{$cfg{'cipherrange'}})) {
            next if $txt =~ m/^\s*$/;
            $txt =~ s/^\s*/                /;
            _yeast($txt);
        }
        _yeast(" $_cnt ciphers= @range");
    }
    _yline(" ciphers }");
    return;
} # _yeast_ciphers_list

sub _yeast_targets      {
    #? print information about targets to be processed
    my $trace   = shift;
    my $prefix  = shift;
    my @targets = @_;
    #print " === print internal data structures for a targets === ";
    if (0 == $trace) { # simple list
        printf("%s%14s= [ ", $prefix, "targets");
        foreach my $target (@targets) {
            next if (0 == @{$target}[0]);       # first entry conatins default settings
            printf("%s:%s%s ", @{$target}[2..3,6]);
               # the perlish way instead of get_target_{host,port,path}
        }
        printf("]\n");
    } else {
        printf("%s%14s targets = [\n", $prefix, "# - - - -ARRAY");
        printf("%s#  Index %6s %24s : %5s %10s %5s %-16s %s\n",
                $prefix, "Prot.", "Hostname or IP", "Port", "Auth", "Proxy", "Path", "Orig. Parameter");
        foreach my $target (@targets) {
            #next if (0 == @{$target}[0]);       # first entry conatins default settings
            printf("%s   [%3s] %6s %24s : %5s %10s %5s %-16s %s\n", $prefix, @{$target}[0,1..7]);
        }
        printf("%s%14s ]\n", $prefix, "# - - - -ARRAY");
    }
    return;
} # _yeast_targets

sub _yeast_init {   ## no critic qw(Subroutines::ProhibitExcessComplexity)
    #? print important content of %cfg and %cmd hashes
    #? more output if 1<trace; full output if 2<trace
    return if (0 >= ($cfg{'trace'} + $cfg{'verbose'}));
    local $\ = "\n";
    my $arg = " (does not exist)";
    ## no critic qw(Variables::ProhibitPackageVars); they are intended here
    if (-f $cfg{'RC-FILE'}) { $arg = " (exists)"; }
    _yeast("!!Hint: use --trace=2  to see Net::SSLinfo variables") if (2 > $cfg{'trace'});
    _yeast("!!Hint: use --trace=2  to see external commands")      if (2 > $cfg{'trace'});
    _yeast("!!Hint: use --trace=3  to see full %cfg")              if (3 > $cfg{'trace'});
    _ynull();
    _yeast("#") if (3 > $cfg{'trace'});
    _yline("");
    _yTRAC("_yeast_init::SID", $SID_dbx) if (2 > $cfg{'trace'});
    _yTRAC("$0", _VERSION());    # $0 is same as $ARG0
    # official VERSIONs, not those of the current files !
    _yTRAC("::osaft",  $osaft::VERSION);
    _yTRAC("Net::SSLhello", $Net::SSLhello::VERSION) if defined($Net::SSLhello::VERSION);
    _yTRAC("Net::SSLinfo",  $Net::SSLinfo::VERSION);
    # quick info first
    _yTRAC("RC-FILE", $cfg{'RC-FILE'} . $arg);
    _yTRAC("--rc",    ((grep{/(?:--rc)$/i}     @ARGV) > 0)? 1 : 0);
    _yTRAC("--no-rc", ((grep{/(?:--no.?rc)$/i} @ARGV) > 0)? 1 : 0);
    _yTRAC("verbose", $cfg{'verbose'});
    _yTRAC("trace",  "$cfg{'trace'}, traceARG=$cfg{'out'}->{'traceARG'}, traceCMD=$cfg{'out'}->{'traceCMD'}, traceKEY=$cfg{'out'}->{'traceKEY'}, traceTIME=$cfg{'out'}->{'traceTIME'}");
    _yTRAC("time_absolut", $cfg{'out'}->{'time_absolut'});
    _yTRAC("dbx{file}", "[ " . join(", ", @{$dbx{'file'}}) . " ]");

    if (1 < $cfg{'trace'}) {
        _yline(" Net::SSLinfo {");
        _yTRAC("::trace",         $Net::SSLinfo::trace);
        _yTRAC("::linux_debug",   $Net::SSLinfo::linux_debug);
        _yTRAC("::slowly",        $Net::SSLinfo::slowly);
        _yTRAC("::timeout",       $Net::SSLinfo::timeout);
        _yTRAC("::use_openssl",   $Net::SSLinfo::use_openssl);
        _yTRAC("::use_sclient",   $Net::SSLinfo::use_sclient);
        _yTRAC("::use_extdebug",  $Net::SSLinfo::use_extdebug);
        _yTRAC("::use_nextprot",  $Net::SSLinfo::use_nextprot);
        _yTRAC("::use_reconnect", $Net::SSLinfo::use_reconnect);
        _yTRAC("::use_SNI",       $Net::SSLinfo::use_SNI);
        _yTRAC("::use_http",      $Net::SSLinfo::use_http);
        _yTRAC("::no_cert",       $Net::SSLinfo::no_cert);
        _yTRAC("::no_cert_txt",   $Net::SSLinfo::no_cert_txt);
        _yTRAC("::protos_alpn",   $Net::SSLinfo::protos_alpn);
        _yTRAC("::protos_npn",    $Net::SSLinfo::protos_npn);
        _yTRAC("::sclient_opt",   $Net::SSLinfo::sclient_opt);
        _yTRAC("::ignore_case",   $Net::SSLinfo::ignore_case);
        _yTRAC("::timeout_sec",   $Net::SSLinfo::timeout_sec);
        _yline(" Net::SSLinfo }");
    }

    _yline(" %cmd {");
    if (2 > $cfg{'trace'}) {    # user friendly information
        _yeast("          path= " . ___ARR(@{$cmd{'path'}}));
        _yeast("          libs= " . ___ARR(@{$cmd{'libs'}}));
        _yeast("     envlibvar= $cmd{'envlibvar'}");
        _yeast("       timeout= $cmd{'timeout'}");
        _yeast("       openssl= $cmd{'openssl'}");
    } else {    # full information
        foreach my $key (sort keys %cmd) { _yeast_trac(\%cmd, $key); }
    }
    _yeast("    extopenssl= $cmd{'extopenssl'}");   # user friendly always
    _yeast("use cipher from openssl= $cmd{'extciphers'}");  # dito.
    _yline(" %cmd }");

    if (1 < $cfg{'trace'}) {    # full information
        _yline(" complete %cfg {");
        foreach my $key (sort keys %cfg) {
            if ($key =~ m/(hints|openssl|ssleay|sslerror|sslhello|regex|^out|^use)$/) { # |data
                # TODO: ugly data structures ... should be done by _yTRAC()
                _yeast("# - - - - HASH: $key = {");
                foreach my $k (sort keys %{$cfg{$key}}) {
                    if ($key =~ m/openssl/) {
                        _yTRAC($k, ___ARR(@{$cfg{$key}{$k}}));
                    } else {
                        #_yTRAC($k, $cfg{$key}{$k});
                        _yeast_trac($cfg{$key}, $k);
                    };
                };
                _yeast("# - - - - HASH: $key }");
            } else {
                if ($key =~ m/targets/) {   # TODO: quick&dirty to get full data
                    _yeast_targets($cfg{'trace'}, $cfg{'prefix_verbose'}, @{$cfg{'targets'}});
                } else {
                    if ("time0" eq $key and defined $ENV{'OSAFT_MAKE'}) {
                        # SEE Make:OSAFT_MAKE (in Makefile.pod)
                        my $t0 = $cfg{'time0'};
                        $cfg{'time0'} = $STR{MAKEVAL};
                        _yeast_trac(\%cfg, $key);
                        $cfg{'time0'} = $t0;
                    } else {
                        _yeast_trac(\%cfg, $key);
                    }
                }
            }
        }
        _yline(" %cfg }");
        return;
    }
    # else  user friendly information
    my $sni_name = __undef($cfg{'sni_name'});   # default is Perl's undef
    my $port     = __undef($cfg{'port'});       # default is Perl's undef
    _yline(" user-friendly cfg {");
    _yeast("      ca_depth= $cfg{'ca_depth'}") if defined $cfg{'ca_depth'};
    _yeast("       ca_path= $cfg{'ca_path'}")  if defined $cfg{'ca_path'};
    _yeast("       ca_file= $cfg{'ca_file'}")  if defined $cfg{'ca_file'};
    _yeast("       use_SNI= $Net::SSLinfo::use_SNI, force-sni=$cfg{'use'}->{'forcesni'}, sni_name=$sni_name");
    _yeast("  default port= $port (last specified)");
    _yeast_targets($cfg{'trace'}, $cfg{'prefix_verbose'}, @{$cfg{'targets'}});
    _yeast("     use->http= $cfg{'use'}->{'http'}");
    _yeast("    use->https= $cfg{'use'}->{'https'}");
    _yeast(" out->hostname= $cfg{'out'}->{'hostname'}");
    _yeast("   out->header= $cfg{'out'}->{'header'}");
    foreach my $key (qw(format legacy starttls starttls_delay slow_server_delay cipherrange)) {
        _yTRAC($key, $cfg{$key});
    }
    _yeast("        cipher= " . ___ARR(@{$cfg{'cipher'}}));
    foreach my $key (qw(starttls_phase starttls_error)) {
        _yeast(      "$key= " . ___ARR(@{$cfg{$key}}));
    }
    _yeast("   SSL version= " . ___ARR(@{$cfg{'version'}}));
    printf("%s",__TRAC("SSL versions", "[ "));  # no \n !
    printf("%s=%s ", $_, $cfg{$_}) foreach (@{$cfg{'versions'}});
    printf("]\n");
    _yeast(" special SSLv2= null-sslv2=$cfg{'use'}->{'nullssl2'}, ssl-lazy=$cfg{'use'}->{'ssl_lazy'}");
    _yeast(" ignore output= " . ___ARR(@{$cfg{'ignore-out'}}));
    _yeast(" user commands= " . ___ARR(@{$cfg{'commands_usr'}}));
    _yeast("given commands= " . ___ARR(@{$cfg{'done'}->{'arg_cmds'}}));
    _yeast("      commands= " . ___ARR(@{$cfg{'do'}}));
    _yline(" user-friendly cfg }");
    _yeast("(more information with: --trace=2  or  --trace=3 )") if (1 > $cfg{'trace'});
    # $cfg{'ciphers'} may not yet set, print with _yeast_ciphers_list()
    return;
} # _yeast_init

sub _yeast_exit {
    #? print collected just be program exit
    if (0 < $cfg{'trace'}) {
        _yTRAC("cfg'exitcode'", $cfg{'use'}->{'exitcode'});
        _yTRAC("exit status",   (($cfg{'use'}->{'exitcode'}==0) ? 0 : $checks{'cnt_checks_no'}->{val}));
    }
    _y_CMD("internal administration ..");
    _y_CMD('@cfg{done} {');
    foreach my $key (sort keys %{$cfg{'done'}}) {
        # cannot use  _yeast_trac(\%{$cfg{'done'}}, $key);
        # because we want the CMD prefix here
        my $label = sprintf("  %-10s=", $key);
        if ('arg_cmds' eq $key) {
            _y_CMD("$label\t[" . join(" ", @{$cfg{'done'}->{$key}}) . "]");
        } else {
            _y_CMD("$label\t" . $cfg{'done'}->{$key});
        }
    }
    _y_CMD('@cfg{done} }');
    return;
} # _yeast_exit

sub _yeast_args {
    #? print information about command line arguments
    return if (not _is_cfg_out('traceARG'));
    # using _y_ARG() may be a performance penulty, but it's trace anyway ...
    _yline(" ARGV {");
    _y_ARG("# summary of all arguments and options from command-line");
    _y_ARG("       called program ARG0= " . $cfg{'ARG0'});
    _y_ARG("     passed arguments ARGV= " . ___ARR(@{$cfg{'ARGV'}}));
    _y_ARG("                   RC-FILE= " . $cfg{'RC-FILE'});
    _y_ARG("      from RC-FILE RC-ARGV= ($#{$cfg{'RC-ARGV'}} more args ...)");
    if (0 >= $cfg{'verbose'}) {
    _y_ARG("      !!Hint:  use --v to get the list of all RC-ARGV");
    _y_ARG("      !!Hint:  use --v --v to see the processed RC-ARGV");
                  # NOTE: ($cfg{'trace'} does not work here
    }
    _y_ARG("      from RC-FILE RC-ARGV= " . ___ARR(@{$cfg{'RC-ARGV'}})) if (0 < $cfg{'verbose'});
    my $txt = "[ ";
    foreach my $target (@{$cfg{'targets'}}) {
        next if (0 == @{$target}[0]);   # first entry conatins default settings
        $txt .= sprintf("%s:%s ", @{$target}[2..3]); # the perlish way
    }
    $txt .= "]";
    _y_ARG("         collected targets= " . $txt);
    if (1 < $cfg{'verbose'}) {
    _y_ARG(" #--v { processed files, arguments and options");
    _y_ARG("    read files and modules= ". ___ARR(@{$dbx{file}}));
    _y_ARG("processed  exec  arguments= ". ___ARR(@{$dbx{exe}}));
    _y_ARG("processed normal arguments= ". ___ARR(@{$dbx{argv}}));
    _y_ARG("processed config arguments= ". ___ARR(map{"`".$_."'"} @{$dbx{cfg}}));
    _y_ARG(" #--v }");
    }
    _yline(" ARGV }");
    return;
} # _yeast_args

sub _yeast_rcfile {
    #? print content read from RC-FILE ## NOT YET USED ##
    return if (0 >= ($cfg{'trace'} + $cfg{'verbose'}));
    _yline(" RC-FILE {");
    _yline(" RC-FILE }");
    return;
} # _yeast_rcfile {

sub _v_print    { local $\ = "\n"; print $cfg{'prefix_verbose'} . join(" ", @_) if (0 < $cfg{'verbose'}); return; }
sub _v2print    { local $\ = "\n"; print $cfg{'prefix_verbose'} . join(" ", @_) if (1 < $cfg{'verbose'}); return; }
sub _v3print    { local $\ = "\n"; print $cfg{'prefix_verbose'} . join(" ", @_) if (2 < $cfg{'verbose'}); return; }
sub _v4print    { local $\ = "";   print $cfg{'prefix_verbose'} . join(" ", @_) if (3 < $cfg{'verbose'}); return; }
sub _trace      { print $cfg{'prefix_trace'} . $_[0]         if (0 < $cfg{'trace'}); return; }
sub _trace0     { print $cfg{'prefix_trace'}                 if (0 < $cfg{'trace'}); return; }
sub _trace1     { print $cfg{'prefix_trace'} . join(" ", @_) if (1 < $cfg{'trace'}); return; }
sub _trace2     { print $cfg{'prefix_trace'} . join(" ", @_) if (2 < $cfg{'trace'}); return; }
sub _trace3     { print $cfg{'prefix_trace'} . join(" ", @_) if (3 < $cfg{'trace'}); return; }
sub _trace_     { local $\ = "";  print  " " . join(" ", @_) if (0 < $cfg{'trace'}); return; }
# if --trace-arg given
sub _trace_cmd  { printf("%s %s->\n", $cfg{'prefix_trace'}, join(" ",@_)) if (_is_cfg_out('traceCMD')); return; }

sub _vprintme   {
    #? write own version, command-line arguments and date and time
    my ($s,$m,$h,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();
    return if (0 >= ($cfg{'verbose'} + $cfg{'trace'}));
    _yeast("$0 " . _VERSION());
    _yeast("$0 " . join(" ", @{$cfg{'ARGV'}}));
    if (defined $ENV{'OSAFT_MAKE'}) {   # SEE Make:OSAFT_MAKE (in Makefile.pod)
        _yeast("$0 dd.mm.yyyy HH:MM:SS (OSAFT_MAKE exists)");
    } else {
        _yeast("$0 " . sprintf("%02s.%02s.%s %02s:%02s:%02s", $mday, ($mon +1), ($year +1900), $h, $m, $s));
    }
    return;
} # _vprintme

#_____________________________________________________________________________
#_________________________________________________________ internal methods __|

# subs for formatted table
sub __data      { return (_is_member(shift, \@{$cfg{'commands'}}) > 0)   ? "*" : "?"; }
sub __data_title{ return sprintf("=%19s %s %s %s %s %s %s %s", @_); }
sub __data_head { return __data_title("key", "command", " %data  ", "%checks", "cmd-ch.", "short ", "intern ", " score"); }
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
        $data .= __yeast(sprintf("%14s= ", $key) . sprintf("0x%04X 0x%08x",
                                 ${$cfg{'openssl_version_map'}}{$key},
                                 ${$cfg{'openssl_version_map'}}{$key})
                        ) . "\n";
    }
    chomp  $data;   # remove last \n
    return $data;
} # __prot_version

#_____________________________________________________________________________
#____________________________________________________ internal test methods __|

sub _yeast_test_help    {
    local $\ = "\n";
    printf("#%s:\n", (caller(0))[3]);
    print "
=== commands for internal testing ===
=
= Print list of commands for internal testing/information.
=
=   command/option  prints this information
=  ----------------+----------------------------------------------
=   --tests         this text
=   --test-init     data structure  %cfg after initialisation
=   --test-data     overview of all available commands and checks
=   --test-maps     internal data strucures '%cfg{openssl}', '%cfg{ssleay}'
=   --test-prot     internal data according protocols
=   --test-regex    results for applying various texts to regex
=   --test-memory   overview of variables' memory usage
=   --test-methods  available methods for openssl in Net::SSLeay
=   --test-sclient  available options for 'openssl s_client' from Net::SSLeay
=   --test-sslmap   constants for SSL protocols from Net::SSLeay
=   --test-ssleay   information about Net::SSLeay capabilities
=   --test-ciphers-*    various ciphers listings; available with o-saft.pl only
=  ----------------+----------------------------------------------
=";
    # o-saft.tcl --test-o-saft  # just for completeness, not used here
    # NOTE: description above should be similar to those in
    #       OSaft/Doc/help.txt
    return $data;
} # _yeast_test_help

sub _yeast_test_data    {
    local $\ = "\n";
    printf("#%s:\n", (caller(0))[3]);
    print "
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
=";

    my $old;
    my @yeast = ();     # list of potential internal, private commands
    my $cmd = " ";
    print __data_head();
    print __data_line();
    $old = "";
    foreach my $key
            (sort {uc($a) cmp uc($b)}
                @{$cfg{'commands'}}, keys %data, keys %shorttexts, keys %checks
            )
            # we use sort case-insensitively, hence the BLOCK for comparsion
            # it also avoids the warning: sort (...) interpreted as function
    {
        next if ($key eq $old); # unique
        $old = $key;
        if ((not defined $checks{$key}) and (not defined $data{$key})) {
            push(@yeast, $key); # probably internal command
            next;
        }
        $cmd = "+" if (0 < _is_member($key, \@{$cfg{'commands'}})); # command available as is
        $cmd = "-" if ($key =~ /$cfg{'regex'}->{'SSLprot'}/i);      # all SSL/TLS commands are for checks only
        print __data_data(  #__/--- check value -------\    true : false  # column
            $key, $cmd,
            (defined $data{$key})                ? __data( $key) : " ",   # data
            (defined $checks{$key})                     ?   "*"  : " ",   # checks
            ((_is_member($key, \@{$dbx{'cmd-check'}}) > 0)
            || ($key =~ /$cfg{'regex'}->{'SSLprot'}/i)) ?   "*"  : "!",   # cmd-ch.
            (defined $shorttexts{$key})                 ?   "*"  : " ",   # short
            (_is_cfg_intern($key))                      ?   "I"  : " ",   # intern
            (defined $checks{$key}->{score}) ? $checks{$key}->{score} : ".",
            );
    }
# FIXME: @{$dbx{'cmd-check'}} is incomplete when o-saft-dbx.pm is require'd in
#        main; some checks above then fail (mainly those matching
#        $cfg{'regex'}->{'SSLprot'}, hence the dirty additional
#        || ($key =~ /$cfg{'regex'}->{'SSLprot'}/)
#               
    print __data_line();
    print __data_head();
    print "=
=   +  command (key) present
=   I  command is an internal command or alias (ok in column 'intern')
=   -  command (key) used internal for checks only (ok in column 'command')
=   *  key present
=      key not present
=   ?  key in %data present but missing in \$cfg{commands}
=   !  key in %cfg{cmd-check} present but missing in redefined %cfg{cmd-check}
=   .  no score defined in %checks{key}
=
= A shorttext should be available for each command and all data keys, except:
=      cn_nosni, ext_*, valid_*
=
= Internal or summary commands:
=      " . join(" ", @yeast) . "\n";
    return;
} # _yeast_test_data

sub _yeast_test_init    {
    local $\ = "\n";
    local $Data::Dumper::Deparse=1; # parse code, see man Data::Dumper
    my $line = "#--------------------+-------------------------------------------";
    printf("#%s:\n", (caller(0))[3]);
    print "
=== internal data structure: initialisation of %cfg, %data and %checks ===
=
= Print initialised data structure  %data and %checks  after all  command-line
= options have been applied.
=
";
#ah not ok: use Sub::Identify ':all';
    _yline(" %cfg {");  # only data which influences initialisations
    print __yeast("#                key | value");
    print __yeast($line);
    print __INIT("ARGV", ___ARR(@{$cfg{'ARGV'}}));
    _yline(" %cfg{use} {");
    foreach my $key (sort keys %{$cfg{'use'}}) {
        print __INIT($key, $cfg{'use'}{$key});
    }
    _yline(" %cfg{use} }");
    print __yeast($line);
    _yline(" %cfg }");
    _yline(" %data {");
    print __yeast("#                key | value (function code)");
    print __yeast($line);
    foreach my $key (sort keys %data) { # ugly and slow code
        # use Dumper() to get code, returns something like:
        #     $VAR1 = sub {
        #                 package OSaft::Data;
        #                 use warnings;
        #                 use strict;
        #                 Net::SSLinfo::version($_[0], $_[1]);
        #             };
        # the line with "package" occours only if the data is in another namespace
        # we only want the code line, hence remove the others
        my $code = Dumper($data{$key}->{val});
        $code =~ s/^\$VAR.*//;
        $code =~ s/(?:};)?\s*$//g;
        $code =~ s/package\s*.*;//g;
        $code =~ s/use\s*(?:strict|warnings);//g;
        $code =~ s/\n//g;
        $code =~ s/^\s*//g;
        print __INIT($key, $code);
    }
    print __yeast($line);
    _yline(" %data }");
    _yline(" %checks {");
    print __yeast("#                key | value");
    print __yeast($line);
    foreach my $key (sort keys %checks) {
        print __INIT($key, $checks{$key}->{val});
    }
    print __yeast($line);
    _yline(" %checks }");
    return;
} # _yeast_test_init

sub _yeast_test_maps    {
    printf("#%s:\n", (caller(0))[3]);
    print "
=== internal data structure %cfg{openssl}, %cfg{ssleay} ===
=
= Print internal mappings for openssl functionality (mainly options).
=
";
    local $\ = "\n";
    my $data = Net::SSLinfo::test_sslmap();
       $data =~ s/^#/#$cfg{'me'}/smg;
    print $data;
    _yline(" %cfg{openssl_option_map} {");
    print __prot_option();
    _yline(" %cfg{openssl_version_map} {");
    print __prot_version();
    return;
} # _yeast_test_maps

sub _yeast_test_prot    {
    printf("#%s:\n", (caller(0))[3]);
    print "
=== internal data structure according protocols ===
=
= Print information about SSL/TLS protocols in various internal variables.
=
";
    local $\ = "\n";
    my $ssl = $cfg{'regex'}->{'SSLprot'};
    _ynull("\n");
    _yline(" %cfg {");
    foreach my $key (sort keys %cfg) {
        # targets= is array of arrays, prints ARRAY ref here only
        _yeast_trac(\%cfg, $key) if ($key =~ m/$ssl/);
    }
    _yline(" }");
    _yline(" %cfg{openssl_option_map} {");
    print __prot_option();
    _yline(" }");
    _yline(" %cfg{openssl_version_map} {");
    print __prot_version();
    _yline(" }");
    # %check_conn and %check_dest are temporary and should be inside %checks
    _yline(" %checks {");
    foreach my $key (sort keys %checks) {
        # $checks{$key}->{val} undefined at beginning
        _yeast(sprintf("%14s= ", $key) . $checks{$key}->{txt}) if ($key =~ m/$ssl/);
    }
    _yline(" }");
    _yline(" %shorttexts {");
    foreach my $key (sort keys %shorttexts) {
        _yeast(sprintf("%14s= ",$key) . $shorttexts{$key}) if ($key =~ m/$ssl/);
    }
    _yline(" }");
    if (0 < ($cfg{'trace'} + $cfg{'verbose'})){
    }
    return;
} # _yeast_test_prot

sub _yeast_test_methods {
    printf("#%s:\n", (caller(0))[3]);
    print "
=== internal list of methods to call openssl ===
=
= Print available methods in Net::SSLeay.
=
";
    my $list = Net::SSLinfo::test_methods();
       $list =~ s/ /\n# /g;
    print "# $list";
    return;
} # _yeast_test_methods

sub _yeast_test_sclient {
    printf("#%s:\n", (caller(0))[3]);
    print "
=== internal list of openssl s_client options ===
=
= Print available options for 'openssl s_client' from Net::SSLeay.
=
";
    my $list = Net::SSLinfo::test_sclient();
       $list =~ s/ /\n# /g;
    print "# $list";
    return;
} # _yeast_test_sclient

sub _yeast_test_sslmap  {
    printf("#%s:\n", (caller(0))[3]);
    print "
=== internal list of constants for SSL protocols ===
=
= Print available constants for SSL protocols in Net::SSLeay.
=
";
    print Net::SSLinfo::test_sslmap();
    return;
} # _yeast_test_sslmap

sub _yeast_test_ssleay  {
    printf("#%s:\n", (caller(0))[3]);
    print "
=== internal data of from Net::SSLeay ===
=
= Print information about Net::SSLeay capabilities.
=
";
    print Net::SSLinfo::test_ssleay();
    return;
} # _yeast_test_ssleay

sub _yeast_test_memory  {
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
    print "
=== memory usage of internal variables ===
=
= Use  --v  to get more details.
=
";
    if (0 < ($cfg{'trace'} + $cfg{'verbose'})){
        foreach my $k (keys %cfg) {
	    printf("%6s\t%s\n", Devel::Size::total_size(\$cfg{$k}),    "%cfg{$k}");
        }
        foreach my $k (keys %checks) {
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
} # _yeast_test_memory

sub _yeast_test {
    #? dispatcher for internal tests, initiated with option --test-*
    my $arg = shift;    # normalised option, like --testinit, --testcipherlist
    _yeast($arg);
    OSaft::Ciphers::show($arg)  if ($arg =~ /^--test[._-]?cipher/);
    _yeast_test_help()          if ('--test'          eq $arg);
    _yeast_test_help()          if ('--tests'         eq $arg);
    _yeast_test_sclient()       if ('--testsclient'   eq $arg); # Net::SSLinfo
    _yeast_test_ssleay()        if ('--testssleay'    eq $arg); # Net::SSLinfo
    _yeast_test_sslmap()        if ('--testsslmap'    eq $arg); # Net::SSLinfo
    _yeast_test_methods()       if ('--testmethods'   eq $arg); # Net::SSLinfo
    _yeast_test_memory()        if ('--testmemory'    eq $arg);
    $arg =~ s/^[+-]-?tests?[._-]?//; # remove --test
    osaft::test_cipher_regex()  if ('regex'           eq $arg);
    _yeast_test_data()          if ('data'            eq $arg);
    _yeast_test_init()          if ('init'            eq $arg);
    _yeast_test_maps()          if ('maps'            eq $arg);
    _yeast_test_prot()          if ('prot'            eq $arg);
    $arg =~ s/^ciphers?[._-]?//;    # allow --test-cipher* and --test-cipher-*
    OSaft::Ciphers::show($arg)  if ($arg =~ /^cipher/); # allow --test-cipher* and cipher-*
    if ('list' eq $arg) {
        # _yeast_ciphers_list() relies on some special $cfg{} settings
        # enforce printing cipher information by adding  +cipher, this
        # should not harm other functionality, as _yeast_test() is for
        # debugging only and will exit then
        $cfg{'verbose'} = 1;
        push(@{$cfg{'do'}}, 'cipher'); # enforce printing cipher informations
        push(@{$cfg{'version'}}, 'TLSv1') if (0 > $#{$cfg{'version'}});
        _yeast_ciphers_list();
    }
    return;
} # _yeast_test

#_____________________________________________________________________________
#_____________________________________________________________________ main __|

sub _main_dbx       {
    my $arg = shift || "--help";    # without argument print own help
    ## no critic qw(InputOutput::RequireEncodingWithUTF8Layer)
    #   see t/.perlcriticrc for detailed description of "no critic"
    #  SEE Perl:binmode()
    binmode(STDOUT, ":unix:utf8");
    binmode(STDERR, ":unix:utf8");
    print_pod($0, __FILE__, $SID_dbx)   if ($arg =~ m/--?h(elp)?$/x);   # print own help
    # else
    # ----------------------------- commands
    if ($arg eq 'version')              { print "$SID_dbx\n"; exit 0; }
    if ($arg =~ m/^[-+]?V(ERSION)?$/)   { print "$VERSION\n"; exit 0; }
    if ($arg =~ m/--tests?$/) { _yeast_test_help(); exit 0; }
    if ($arg =~ m/--(yeast|test)[_.-]?(.*)/) {
        $arg = "--test-$2";
        printf("#$0: direct testing not yet possible, please try:\n   o-saft.pl $arg\n");
    }
    exit 0;
} # _main_dbx

sub dbx_done        {}; # dummy to check successful include

#_____________________________________________________________________________
#_____________________________________________________ public documentation __|

=pod

=encoding utf8

=head1 NAME

o-saft-dbx.pm - module for tracing o-saft.pl


=head1 SYNOPSIS

=over 2

=item require "o-saft-dbx.pm";

=item o-saft-dbx.pm <L<OPTIONS|OPTIONS>>

=back


=head1 OPTIONS

=over 2

=item --help

=item --tests

List available commands or options for internal testing.

=item --test-ciphers-list

=item --test-ciphers-show

=item --test-ciphers-sort

=item --test-ciphers-overview

=item --test-regex

=item --test-data

=item --test-init

=item --test-maps

=item --test-prot

See  I<--tests>  for description of these options.

=back


=head1 DESCRIPTION

Defines all functions needed for trace and debug output in  L<o-saft.pl|o-saft.pl>.


=head1 METHODS

Functions being used in L<o-saft.pl|o-saft.pl> should be defined as empty stub there.
For example:

    sub _yeast_init() {}

=head3 _yeast_ciphers_list( )

=head3 _yeast_trac( )

=head3 _yeast_init( )

=head3 _yeast_exit( )

=head3 _yeast_args( )

=head3 _yeast( )

=head3 _y_ARG( ), _y_CMD( ), _yline( )

=head3 _vprintme( )

=head3 _v_print( ), _v2print( ), _v3print( ), _v4print( )

=head3 _trace( ), _trace1( ), _trace2( ), _trace_cmd( )

=head2 Functions for internal testing; initiated with option  C<--test-*>

=head3 _yeast_test_help( )

=head3 _yeast_test_data( )

=head3 _yeast_test_init( )

=head3 _yeast_test_maps( )

=head3 _yeast_test_prot( )

=head3 _yeast_test_methods( )

=head3 _yeast_test_sclient( )

=head3 _yeast_test_sslmap( )

=head3 _yeast_test_ssleay( )

=head3 _yeast_test( )

=head2 VARIABLES

Variables which may be used herein must be defined as `our' in L<o-saft.pl|o-saft.pl>:

=head3 $SID_main

=head3 %data

=head3 %cfg, i.e. trace, traceARG, traceCMD, traceKEY, time_absolut, verbose

=head3 %checks

=head3 %dbx

=head3 $time0


=head1 SPECIALS

If you want to do special debugging, you can define proper functions here.
They don't need to be defined in L<o-saft.pl|o-saft.pl> if they are used only here.
In that case simply call the function in C<_yeast_init> or C<_yeast_exit>
they are called at beginning and end of L<o-saft.pl|o-saft.pl>.
It's just important that  L<o-saft.pl|o-saft.pl>  was called with either the I<--v>
or any I<--trace*>  option, which then loads this file automatically.


=head1 VERSION

2.29 2023/11/13

=head1 AUTHOR

13-nov-13 Achim Hoffmann

=cut

## PACKAGE }

#_____________________________________________________________________________
#_____________________________________________________________________ self __|

_main_dbx(@ARGV) if (not defined caller);

1;
