#!/usr/bin/perl
## PACKAGE {

#!# Copyright (c) Achim Hoffmann, sic[!]sec GmbH
#!# This  software is licensed under GPLv2. Please see o-saft.pl for details.

## no critic qw(Documentation::RequirePodSections)
#  our POD below is fine, perlcritic (severity 2) is too pedantic here.

=pod

=head1 NAME

o-saft-dbx.pm - module for tracing o-saft.pl

=head1 SYNOPSIS

require "o-saft-dbx.pm";

=head1 DESCRIPTION

Defines all function needed for trace and debug output in  L<o-saft.pl|o-saft.pl>.

=head2 Functions defined herein

=over 4

=item _yeast_init( )

=item _yeast_exit( )

=item _yeast_args( )

=item _yeast_data( )

=item _yeast_prot( )

=item _yeast_cipher( )

=item _yeast( )

=item _y_ARG( ), _y_CMD( ), _yline( )

=item _vprintme( )

=item _v_print( ), _v2print( ), _v3print( ), _v4print( )

=item _trace( ), _trace1( ), _trace2( ), _trace_cmd( )

=back

=head2 Variables which may be used herein

They must be defined as `our' in L<o-saft.pl|o-saft.pl>:

=over 4

=item $VERSION

=item %data

=item %cfg, i.e. trace, traceARG, traceCMD, traceKEY, verbose

=item %checks

=item %dbx

=back

Functions being used in L<o-saft.pl|o-saft.pl> shoudl be defined as empty stub there.
For example:

    sub _yeast_init() {}

=head1 SPECIALS

If you want to do special debugging, you can define proper functions here.
They don't need to be defined in L<o-saft.pl|o-saft.pl> if they are used only here.
In that case simply call the function in C<_yeast_init> or C<_yeast_exit>
they are called at beginning and end of L<o-saft.pl|o-saft.pl>.
It's just important that  L<o-saft.pl|o-saft.pl>  was called with either the I<--v>
or any I<--trace*>  option, which then loads this file automatically.

=cut

## no critic qw(TestingAndDebugging::RequireUseStrict)
#  `use strict;' not usefull here, as we mainly use our global variables
use warnings;

my  $DBX_SID= "@(#) o-saft-dbx.pm 1.43 16/05/15 17:10:41";

package main;   # ensure that main:: variables are used, if not defined herein

no warnings 'redefine'; ## no critic qw(TestingAndDebugging::ProhibitNoWarnings)
   # must be herein, as most subroutines are already defined in main
   # warnings pragma is local to this file!
no warnings 'once';     ## no critic qw(TestingAndDebugging::ProhibitNoWarnings)
   # "... used only once: possible typo ..." appears when called as main only

## no critic qw(Subroutines::RequireArgUnpacking)
#        parameters are ok for trace output

## no critic qw(ValuesAndExpressions::ProhibitNoisyQuotes)
#        we have a lot of single character strings, herein, that's ok


# debug functions
sub _y_ts     { if ($cfg{'traceTIME'} <= 0){ return ""; } return sprintf(" %02s:%02s:%02s", (localtime)[2,1,0]); }
sub _yeast($) { local $\ = "\n"; print "#" . $cfg{'mename'} . ": " . $_[0]; return; }
sub _y_ARG    { local $\ = "\n"; print "#" . $cfg{'mename'} . " ARG: " . join(" ", @_) if ($cfg{'traceARG'} > 0); return; }
sub _y_CMD    { local $\ = "\n"; print "#" . $cfg{'mename'} . _y_ts() . " CMD: " . join(" ", @_) if ($cfg{'traceCMD'} > 0); return; }
sub _yTRAC($$){ local $\ = "\n"; printf("#%s: %14s= %s\n", $cfg{'mename'}, $_[0], $_[1]); return; }
sub _yline($) { _yeast("#----------------------------------------------------" . $_[0]); return; }
sub _y_ARR(@) { return join(" ", "[", @_, "]"); }
sub _yeast_trac($$){}   # forward declaration
sub _yeast_trac($$){
    #? print variable according its type, undertands: CODE, SCALAR, ARRAY, HASH
    my $ref  = shift;   # must be a hash reference
    my $key  = shift;
    if (! defined $ref->{$key}) {
        # undef is special, avoid perl warnings
        _yTRAC($key, "<<null>>");
        return;
    }
    SWITCH: for (ref($ref->{$key})) {   # ugly but save use of $_ here
        /^$/    && do { _yTRAC($key, $ref->{$key}); last SWITCH; }; ## no critic qw(RegularExpressions::ProhibitFixedStringMatches)
        /CODE/  && do { _yTRAC($key, "<<code>>");   last SWITCH; };
        /SCALAR/&& do { _yTRAC($key, $ref->{$key}); last SWITCH; };
        /ARRAY/ && do { _yTRAC($key, _y_ARR(@{$ref->{$key}})); last SWITCH; };
        /HASH/  && do { last SWITCH if ($ref->{'trace'} <= 2);      # print hashes for full trace only
                        _yeast("# - - - - HASH: $key = {");
                        foreach my $k (sort keys %{$ref->{$key}}) {
                            #_yeast_trac($ref, $key); # FIXME: causes infinite loop
                            _yTRAC("    ".$key."->".$k, ""); # TODO: join("-", @{$ref->{$key}->{$k}}))
                        };
                        _yeast("# - - - - HASH: $key }");
                        last SWITCH;
                    };
        # DEFAULT
                        warn STR_WARN . " user defined type '$_' skipped";
    } # SWITCH

    return;
} # _yeast_trac()

sub _yeast_init() {
    #? print important content of %cfg and %cmd hashes
    #? more output if trace>1; full output if trace>2
    return if (($cfg{'trace'} + $cfg{'verbose'}) <= 0);
    _yline("");
    _yTRAC("$0", $VERSION);
    _yTRAC("_yeast_init::SID", $DBX_SID) if ($cfg{'trace'} > 2);
    _yTRAC("Net::SSLhello", $Net::SSLhello::VERSION) if defined($Net::SSLhello::VERSION);
    _yTRAC("Net::SSLinfo",  $Net::SSLinfo::VERSION);
    ## no critic qw(Variables::ProhibitPackageVars)
    if ($cfg{'trace'} > 1) {
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
        _yTRAC("::protocols",     $Net::SSLinfo::protocols);
        _yTRAC("::sclient_opt",   $Net::SSLinfo::sclient_opt);
        _yTRAC("::ignore_case",   $Net::SSLinfo::ignore_case);
        _yTRAC("::timeout_sec",   $Net::SSLinfo::timeout_sec);
        _yline(" Net::SSLinfo }");
    }
    ## use critic
    _yTRAC("verbose", $cfg{'verbose'});
    _yTRAC("trace",  "$cfg{'trace'}, traceARG=$cfg{'traceARG'}, traceCMD=$cfg{'traceCMD'}, traceKEY=$cfg{'traceKEY'}, traceTIME=$cfg{'traceTIME'}");
    # more detailed trace first
    if ($cfg{'trace'} > 1){
        _yline(" %cmd {");
        foreach my $key (sort keys %cmd) {
            _yeast_trac(\%cmd, $key);
        }
        _yline(" %cmd }");
        _yline(" complete %cfg {");
        foreach my $key (sort keys %cfg) {
            if ($cfg{'trace'} <= 2){
                next if $key =~ /^cmd-/; # print internal list of command for full trace only
            }
            _yeast_trac(\%cfg, $key);
        }
        _yline(" %cfg }");
    }
    # now user friendly informations
    _yline(" cmd {");
    _yeast("# " . join(", ", @{$dbx{'file'}}));
    _yeast("          path= " . _y_ARR(@{$cmd{'path'}}));
    _yeast("          libs= " . _y_ARR(@{$cmd{'libs'}}));
    _yeast("     envlibvar= $cmd{'envlibvar'}");
    _yeast("  cmd->timeout= $cmd{'timeout'}");
    _yeast("  cmd->openssl= $cmd{'openssl'}");
    _yeast("   use_openssl= $cmd{'extopenssl'}");
    _yeast("openssl cipher= $cmd{'extciphers'}");
    _yline(" cmd }");
    _yline(" user-friendly cfg {");
    _yeast("      ca_depth= $cfg{'ca_depth'}") if defined $cfg{'ca_depth'};
    _yeast("       ca_path= $cfg{'ca_path'}")  if defined $cfg{'ca_path'};
    _yeast("       ca_file= $cfg{'ca_file'}")  if defined $cfg{'ca_file'};
    _yeast("       use_SNI= $Net::SSLinfo::use_SNI, force-sni=$cfg{'forcesni'}, sni_name=$cfg{'sni_name'}");
    _yeast("  default port= $cfg{'port'} (last specified)");
    _yeast("       targets= " . _y_ARR(@{$cfg{'hosts'}}));
    foreach my $key (qw(out_header format legacy usehttp usedns usemx starttls starttlsDelay cipherrange)) {
        printf("#%s: %14s= %s\n", $cfg{'mename'}, $key, $cfg{$key});
           # cannot use _yeast() 'cause of pretty printing
    }
    _yeast("   SSL version= " . _y_ARR(@{$cfg{'version'}}));
    printf("#%s: %14s= %s", $cfg{'mename'}, "SSL versions", "[ ");
    printf("%s=%s ", $_, $cfg{$_}) foreach (@{$cfg{'versions'}});
    printf("]\n");
    _yeast(" special SSLv2= null-sslv2=$cfg{'nullssl2'}, ssl-lazy=$cfg{'ssl_lazy'}");
    _yeast(" ignore output= " . _y_ARR(@{$cfg{'ignore-out'}}));
    _yeast("given commands= " . _y_ARR(@{$cfg{'done'}->{'arg_cmds'}}));
    _yeast("      commands= " . _y_ARR(@{$cfg{'do'}}));
    _yeast("        cipher= " . _y_ARR(@{$cfg{'cipher'}}));
    _yline(" user-friendly cfg }");
    _yeast("(more information with: --trace=2  or  --trace=3 )") if ($cfg{'trace'} < 1);
    return;
} # _yeast_init

sub _yeast_exit() {
    _y_CMD("internal administration ..");
    _y_CMD("cfg'done'{");
    _y_CMD("  $_ : " . $cfg{'done'}->{$_}) foreach (sort keys %{$cfg{'done'}});
    _y_CMD("cfg'done'}");
    return;
} # _yeast_exit

sub _yeast_args() {
    return if ($cfg{'traceARG'} <= 0);
    # using _y_ARG() may be a performance penulty, but it's trace anyway ...
    _yline(" ARGV {");
    _y_ARG("# summary of all arguments and options from command line");
    _y_ARG("       called program ARG0= " . $cfg{'ARG0'});
    _y_ARG("     passed arguments ARGV= " . _y_ARR(@{$cfg{'ARGV'}}));
    _y_ARG("                   RC-FILE= " . $cfg{'RC-FILE'});
    _y_ARG("      from RC-FILE RC-ARGV= ($#{$cfg{'RC-ARGV'}} more args ...)");
    if ($cfg{'verbose'} <= 0) {
    _y_ARG("      # hint: use --v to get the list of all RC-ARGV");
    _y_ARG("      # hint: use --v --v to see the processed RC-ARGV");
                  # NOTE: ($cfg{'trace'} does not work here
    }
    _y_ARG("      from RC-FILE RC-ARGV= " . _y_ARR(@{$cfg{'RC-ARGV'}})) if ($cfg{'verbose'} > 0);
    _y_ARG("           collected hosts= " . _y_ARR(@{$cfg{'hosts'}}));
    if ($cfg{'verbose'} > 1) {
    _y_ARG(" #--v { processed files, arguments and options");
    _y_ARG("    read files and modules= ". _y_ARR(@{$dbx{file}}));
    _y_ARG("processed  exec  arguments= ". _y_ARR(@{$dbx{exe}}));
    _y_ARG("processed normal arguments= ". _y_ARR(@{$dbx{argv}}));
    _y_ARG("processed config arguments= ". _y_ARR(map{"`".$_."'"} @{$dbx{cfg}}));
    _y_ARG(" #--v }");
    }
    _yline(" ARGV }");
    return;
} # _yeast_args

sub _v_print  { local $\ = "\n"; print "# "       . join(" ", @_) if ($cfg{'verbose'} >  0); return; }
sub _v2print  { local $\ = "";   print "# "       . join(" ", @_) if ($cfg{'verbose'} == 2); return; } # must provide \n if wanted
sub _v3print  { local $\ = "\n"; print "# "       . join(" ", @_) if ($cfg{'verbose'} == 3); return; }
sub _v4print  { local $\ = "";   print "# "       . join(" ", @_) if ($cfg{'verbose'} == 4); return; }
sub _trace($) { print "#" . $cfg{'mename'} . "::" . $_[0]         if ($cfg{'trace'} > 0); return; }
sub _trace0($){ print "#" . $cfg{'mename'} . "::"                 if ($cfg{'trace'} > 0); return; }
sub _trace1($){ print "#" . $cfg{'mename'} . "::" . join(" ", @_) if ($cfg{'trace'} > 1); return; }
sub _trace2($){ print "#" . $cfg{'mename'} . "::" . join(" ", @_) if ($cfg{'trace'} > 2); return; }
sub _trace3($){ print "#" . $cfg{'mename'} . "::" . join(" ", @_) if ($cfg{'trace'} > 3); return; }
sub _trace_($){ local $\ = "";  print  " " . join(" ", @_) if ($cfg{'trace'} > 0); return; }
# if --trace-arg given
sub _trace_cmd($) { printf("#%s %s->\n", $cfg{'mename'}, join(" ",@_))if ($cfg{'traceCMD'} > 0); return; }

sub _vprintme {
    my ($s,$m,$h,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();
    _v_print("$0 " . $VERSION);
    _v_print("$0 " . join(" ", @{$cfg{'ARGV'}}));
    _v_print("$0 " . sprintf("%02s.%02s.%s %02s:%02s:%02s", $mday, ($mon +1), ($year +1900), $h, $m, $s));
    return;
} # _vprintme

sub __data($) { return (_is_member(shift, \@{$cfg{'commands'}}) > 0)   ? "*" : "?"; }
sub _yeast_data() {
    print "
=== _yeast_data: check internal data structure ===

  This function prints a simple overview of all available commands and checks.
  The purpose is to show if a proper key is defined in  %data and %checks  for
  each command from  %cfg{'commands'}  and vice versa.
";

    my $old;
    my @yeast = ();     # list of potential internal, private commands
    my $cmd = " ";
    printf("%20s %s %s %s %s %s %s %s\n", "key", "command", "intern ", "  data  ", "short ", "checks ", "cmd-ch.", " score");
    printf("%20s+%s+%s+%s+%s+%s+%s+%s\n", "-"x20, "-"x7, "-"x7, "-"x7, "-"x7, "-"x7, "-"x7, "-"x7);
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
        if ((! defined $checks{$key}) and (! defined $data{$key})) {
            push(@yeast, $key); # probaly internal command
            next;
        }
        $cmd = "+" if (_is_member($key, \@{$cfg{'commands'}}) > 0);     # command available as is
        $cmd = "-" if ($key =~ /$cfg{'regex'}->{'SSLprot'}/);           # all SSL/TLS commands ar for checks only
        printf("%20s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", $key,
            $cmd,
            (_is_intern($key) > 0)      ?          "I"  : " ",
            (defined $data{$key})       ? __data( $key) : " ",
            (defined $shorttexts{$key}) ?          "*"  : " ",
            (defined $checks{$key})     ?          "*"  : " ",
            ((_is_member($key, \@{$dbx{'cmd-check'}}) > 0)
            || ($key =~ /$cfg{'regex'}->{'SSLprot'}/)) ? "*"  : "!",
            (defined $checks{$key}->{score}) ? $checks{$key}->{score} : ".",
            );
    }
# FIXME: FIXME: @{$dbx{'cmd-check'}} is incomplete when o-saft-dbx.pm is 
#               `require'd in main; some checks above fail (mainly those
#               those matching $cfg{'regex'}->{'SSLprot'}, hence the dirty
#               additional  || ($key =~ /$cfg{'regex'}->{'SSLprot'}/)
#               
    printf("%20s+%s+%s+%s+%s+%s+%s+%s\n", "-"x20, "-"x7, "-"x7, "-"x7, "-"x7, "-"x7, "-"x7, "-"x7);
    printf("%20s %s %s %s %s %s %s %s\n", "key", "command", "intern ", "  data  ", "short ", "checks ", "cmd-ch.", " score");
    print '
    +  command (key) present
    I  command is an internal command or alias
    -  command (key) used internal for checks only
    *  key present
       key not present
    ?  key in %data present but missing in $cfg{commands}
    !  key in %cfg{cmd-check} present but missing in redefined %cfg{cmd-check}
    .  no score defined in %checks{key}

    A shorttext should be available for each command and all data keys, except:
        cn_nosni, ext_*, valid-*

    Please check following keys, they skipped in table above due to
    ';
    print "    internal or summary commands:\n        " . join(" ", @yeast);
    print "\n";
    return;
} # _yeast_data
sub _yeast_prot() {
    #? print information about SSL/TLS protocols in various variables (hashes)
    #? this function is for internal use only
    local $\ = "\n";
    my $ssl = $cfg{'regex'}->{'SSLprot'};
    print "=== _yeast_prot: internal data according protocols ===\n";
        _yline(" %cfg {");
        foreach my $key (sort keys %cfg) {
            #printf("%16s= %s\n", $key, $cfg{$key}) if ($key =~ m/$ssl/);
            _yeast_trac(\%cfg, $key) if ($key =~ m/$ssl/);
        }
        _yline(" }");
        _yline(" %cfg{openssl_option_map} {");
        foreach my $key (sort keys %{$cfg{'openssl_option_map'}})  {
            _yeast_trac(\%{$cfg{'openssl_option_map'}}, $key);
        }
        _yline(" }");
        _yline(" %cfg{openssl_version_map} {");
        foreach my $key (sort keys %{$cfg{'openssl_version_map'}}) {
            _yeast(sprintf("%14s= ", $key) . sprintf("0x%04x (%d)", ${$cfg{'openssl_version_map'}}{$key}, ${$cfg{'openssl_version_map'}}{$key}));
        }
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
    if (($cfg{'trace'} + $cfg{'verbose'}) >  0){
    }
    return;
} # _yeast_prot()

sub _yeast_cipher() {
# TODO: %ciphers %cipher_names
}

sub o_saft_dbx_done() {};       # dummy to check successful include
## PACKAGE }

unless (defined caller) {
    if (eval {require POD::Perldoc;}) {
        # pod2usage( -verbose => 1 )
        exit( Pod::Perldoc->run(args=>[$0]) );
    }
    if (qx(perldoc -V)) {
        # may return:  You need to install the perl-doc package to use this program.
        #exec "perldoc $0"; # scary ...
        print "# try:\n  perldoc $0\n";
    }
}

1;
