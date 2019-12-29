#!/usr/bin/perl
## PACKAGE {

#!# Copyright (c) 2019 Achim Hoffmann, sic[!]sec GmbH
#!# This  software is licensed under GPLv2. Please see o-saft.pl for details.

## no critic qw(Documentation::RequirePodSections)
#  our POD below is fine, perlcritic (severity 2) is too pedantic here.

# HACKER's INFO
#       Following (internal) functions from o-saft.pl are used:
#       _is_do()
#       _is_intern()
#       _is_member()
#       _need_cipher()
#       _get_ciphers_range()

## no critic qw(TestingAndDebugging::RequireUseStrict)
#  `use strict;' not usefull here, as we mainly use our global variables
use warnings;

my  $SID_dbx= "@(#) o-saft-dbx.pm 1.111 19/12/29 08:47:41";

package main;   # ensure that main:: variables are used, if not defined herein

no warnings 'redefine'; ## no critic qw(TestingAndDebugging::ProhibitNoWarnings)
   # must be herein, as most subroutines are already defined in main
   # warnings pragma is local to this file!
no warnings 'once';     ## no critic qw(TestingAndDebugging::ProhibitNoWarnings)
   # "... used only once: possible typo ..." appears when called as main only

## no critic qw(Subroutines::RequireArgUnpacking)
#        Parameters are ok for trace output.

## no critic qw(ValuesAndExpressions::ProhibitNoisyQuotes)
#        We have a lot of single character strings, herein, that's ok.

## no critic qw(ValuesAndExpressions::ProhibitMagicNumbers)
#        We have some constants herein, that's ok.

## no critic qw(Subroutines::ProhibitUnusedPrivateSubroutines)
#        That's intended.

## no critic qw(ValuesAndExpressions::ProhibitImplicitNewlines)
#        That's intended in strings; perlcritic is too pedantic.

## no critic qw(RegularExpressions::RequireExtendedFormatting)
#        We believe that most RegEx are not too complex.

# debug functions
sub _yTIME      {
    if (0 >= $cfg{'traceTIME'}) { return ""; }
    my $now = time() - ($time0 || 0);
       $now = time() if (1 == $cfg{'time_absolut'});# $time0 defined in main
    return sprintf(" %02s:%02s:%02s", (localtime($now))[2,1,0]);
}
sub __yeast     { return $cfg{'prefix_verbose'} . $_[0]; }
sub ___ARG      { return $cfg{'prefix_verbose'} .            " ARG: " . join(" ", @_); }
sub ___CMD      { return $cfg{'prefix_verbose'} . _yTIME() . " CMD: " . join(" ", @_); }
sub __line      { return "#----------------------------------------------------" . $_[0]; }
sub ___ARR      { return join(" ", "[", @_, "]"); }
sub __TRAC      { return sprintf("%s%14s= %s", $cfg{'prefix_verbose'}, $_[0], $_[1]);  }
sub _y_ARG      { local $\ = "\n"; print ___ARG(@_) if (0 < $cfg{'traceARG'}); return; }
sub _y_CMD      { local $\ = "\n"; print ___CMD(@_) if (0 < $cfg{'traceCMD'}); return; }
sub _yeast      { local $\ = "\n"; print __yeast($_[0]);return; }
sub _yTRAC      { local $\ = "\n"; print __TRAC(@_);    return; }
sub _yline      { _yeast(__line($_[0]));                return; }
sub _ynull      { _yeast("value <<null>> means that internal variable is not defined @_"); return; }
sub __trac      {}          # forward declaration
sub __trac      {
    #? print variable according its type, understands: CODE, SCALAR, ARRAY, HASH
    my $ref  = shift;   # must be a hash reference
    my $key  = shift;
    my $data = "";
    if (not defined $ref->{$key}) {
        # undef is special, avoid perl warnings
        return __TRAC($key, "<<null>>");
    }
    SWITCH: for (ref($ref->{$key})) {   # ugly but save use of $_ here
        /^$/    && do { $data .= __TRAC($key, $ref->{$key}); last SWITCH; };
        /CODE/  && do { $data .= __TRAC($key, "<<code>>");   last SWITCH; };
        /SCALAR/&& do { $data .= __TRAC($key, $ref->{$key}); last SWITCH; };
        /ARRAY/ && do { $data .= __TRAC($key, ___ARR(@{$ref->{$key}})); last SWITCH; };
        /HASH/  && do { last SWITCH if (2 >= $ref->{'trace'});      # print hashes for full trace only
                        $data .= __yeast("# - - - - HASH: $key = {");
                        foreach my $k (sort keys %{$ref->{$key}}) {
                            #__trac($ref, ${$ref->{$key}}{$k}); # FIXME:
                            $data .= __TRAC("    ".$key."->".$k, join("-", ${$ref->{$key}}{$k})); # TODO: fast ok
                        };
                        $data .= __yeast("# - - - - HASH: $key }");
                        last SWITCH;
                    };
        # DEFAULT
                        $data .= __yeast(STR_WARN . " user defined type '$_' skipped");
    } # SWITCH

    return $data;
} # __trac

sub _yeast_trac { local $\ = "\n"; print __trac(@_); return; }
    #? print variable according its type, understands: CODE, SCALAR, ARRAY, HASH

sub _yeast_ciphers_list     { # TODO: obsolete when ciphers defined in OSaft/Cipher.pm
    #? print ciphers fromc %cfg (output optimized for +cipher and +cipherraw)
    return if (0 >= ($cfg{'trace'} + $cfg{'verbose'}));
    _yline(" ciphers {");
    my $_cnt = scalar @{$cfg{'ciphers'}};
    my $need = _need_cipher();
    my $ciphers = "@{$cfg{'ciphers'}}";
    if (_is_do('cipherraw')) {
       $need = 1;
       my @range = $cfg{'cipherranges'}->{$cfg{'cipherrange'}};
       if ($cfg{'cipherrange'} =~ m/(full|huge|safe)/i) {
           # avoid huge (useless output)
           $_cnt = 0xffffff;
           $_cnt = 0x2fffff if ($cfg{'cipherrange'} =~ m/safe/i);
           $_cnt = 0xffff   if ($cfg{'cipherrange'} =~ m/huge/i);
       } else {
           # expand list
           @range = _get_ciphers_range(${$cfg{'version'}}[0], $cfg{'cipherrange'});
              # FIXME: _get_ciphers_range() first arg is the SSL version, which
              #        is usually unknown here, hence the first is passed
              #        this my result in a wrong list; but its trace output only
           $_cnt = scalar @range;
       }
       $ciphers = "@range";
    }
    _yeast("  _need_cipher= $need");
    if (0 < $need) {
        $_cnt = sprintf("%5s", $_cnt);  # format count
        _yeast("      starttls= " . $cfg{'starttls'});
        _yeast("   cipherrange= " . $cfg{'cipherrange'});   # used only if (_is_do('cipherraw')) {
        _yeast(" cipherpattern= " . $cfg{'cipherpattern'});
        _yeast("use cipher from openssl= " . $cmd{'extciphers'});
        _yeast(" $_cnt ciphers= $ciphers");
    }
    _yline(" ciphers }");
    return;
} # _yeast_ciphers_list

sub _yeast_ciphers_sorted   { # TODO: obsolete when ciphers defined in OSaft/Cipher.pm
    printf("#%s:\n", (caller(0))[3]);
    print "
=== ciphers sorted according strength ===
=
= OWASP openssl cipher
=------+-------+----------------------------------------------
";
    my @sorted;
    # TODO: sorting as in yeast.pl _sort_results()
    foreach my $c (sort_cipher_names(keys %ciphers)) {
        push(@sorted, sprintf("%2s\t%s\t%s\n", get_cipher_owasp($c), get_cipher_sec($c), $c));
    }
    print foreach sort @sorted;
    print "=------+-------+----------------------------------------------\n";
    print "= OWASP openssl cipher\n";
    return;
} # _yeast_ciphers_sorted

sub _yeast_ciphers_overview { # TODO: obsolete when ciphers defined in OSaft/Cipher.pm
    printf("#%s:\n", (caller(0))[3]);
    print "
=== internal data structure for ciphers ===
=
= This function prints a simple overview of all available ciphers. The purpose
= is to show if the internal data structure provides all necessary data.
=
=   description of columns:
=       key         - hex key for cipher suite
=       cipher sec. - cipher suite security is known
=       cipher name - cipher suite (openssl) name exists
=       cipher const- cipher suite constant name exists
=       cipher desc - cipher suite known in internal data structure
=       cipher alias- other (alias) cipher suite names exist
=       name # desc - 'yes' if name and description exists
=   description of values:
=       *    value present
=       -    value missing
=       -?-  security unknown/undefined
=       miss security missing in data structure
=
= No perl or other warnings should be printed.
= Note: following columns should have a *
=       security, name, const, desc
=
";
    my $cnt = 0;
    my %err = (
       'key'    => 0,
       'sec'    => 0,
       'name'   => 0,
       'const'  => 0,
       'descr'  => 0,
    );
    print __data_title("",    " cipher",  " cipher", "cipher",  " cipher", " cipher", " name +", " cipher");
    print __data_title("key", "security", " name ",  " const",  "  desc.", "  alias", "  desc.", "  suite");
    print __data_line();
    # key in %ciphers is the cipher suite name, but we want the ciphers sorted
    # according their hex constant; perl's sort need a copare funtion
    my %keys;
    map { $keys{get_cipher_hex($_)} = $_; } keys %ciphers;
    foreach my $k (sort {$a cmp $b} keys %keys) {
        $cnt++;
        my $c   = $keys{$k};
        my $key = get_cipher_hex($c);
           $key = "-" if ($key =~ m/^\s*$/);
        my $sec = get_cipher_sec($c);
           $sec = "*" if ($sec =~ m/$cfg{'regex'}->{'security'}/i);
           $sec = "-" if ($sec =~ m/^\s*$/);
        my $name= (get_cipher_name($c)  =~ m/^\s*$/) ? "-" : "*";
        my $desc= join(" ", get_cipher_desc($c));
           $desc= ($desc =~ m/^\s*$/) ? "-" : "*";
        my $const=(get_cipher_suiteconst($c) =~ m/^\s*$/) ? "*" : "*"; # FIXME: 
        my $alias= "-"; #get_cipher_suitealias($c); # =~ m/^\s*$/) ? "-" : "*";
        my $both= "-";
        $both   = "*" if ('*' eq $desc and '*' eq $name);
        print __data_data( $key, $sec, $name, $const, $desc, $alias, $both, $c);
        $err{'key'}++   if ($key  eq "-");
        $err{'sec'}++   if ($sec  ne "*");
        $err{'name'}++  if ($name ne "*");
       #$err{'cnst'}++  if ($cnst ne "*");
        $err{'desc'}++  if ($desc ne "*");
    }
    print __data_line();
    print __data_title("key", "security", " name  ", "const  ", "descr. ", "  cipher", "", "");
    printf("= %s ciphers\n", $cnt);
    printf("= identified errors: ");
    printf("%6s=%-2s,", $_, $err{$_}) foreach keys %err;
    printf("\n\n");
    return;
} # _yeast_ciphers_overview

sub _yeast_ciphers_show     { # TODO: obsolete when ciphers defined in OSaft/Cipher.pm
    printf("#%s:\n", (caller(0))[3]);
    print "
=== internal data structure for ciphers ===
=
= This function prints a full overview of all available ciphers.
= Output is similar (order of columns) but not identical to result of
= 'openssl ciphers -V' command.
=
=   description of columns:
=       key         - internal hex key for cipher suite
=       hex         - hex key for cipher suite (like opnssl)
=       ssl         - SSL/TLS version
=       keyx        - Key Exchange
=       auth        - Authentication
=       enc         - Encryption Algorithm
=       bits        - Key Size
=       mac         - MAC Algorithm
=       sec         - Security
=       name        - OpenSSL suite name
=
";
    my $cnt = 0;
    printf("=%9s\t%9s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
           "key", "hex", "ssl", "keyx", "auth", "enc", "bits", "mac", "sec", "name");
    printf("=%s+%s+%s\n", "-"x14, "-"x15, "-------+"x8 );
    # key in %ciphers is the cipher suite name, but we want the ciphers sorted
    # according their hex constant; perl's sort need a copare funtion
    my %keys;
    map { $keys{get_cipher_hex($_)} = $_; } keys %ciphers;
    foreach my $k (sort {$a cmp $b} keys %keys) {
        $cnt++;
        my $c   = $keys{$k};
        my $key = get_cipher_hex($c);
        my $hex = tls_key2text($key);
        ## $key = tls_text2key($hex);
        my $ssl = get_cipher_ssl($c);
        my $sec = get_cipher_sec($c);
        my $keyx= get_cipher_keyx($c);
        my $auth= get_cipher_keyx($c);
        my $enc = get_cipher_enc($c);
        my $bits= get_cipher_bits($c);
        my $mac = get_cipher_mac($c);
        my $name= get_cipher_name($c);
        my $desc= join(" ", get_cipher_desc($c));
        my $const=get_cipher_suiteconst($c);
        my $rfc = "-"; # get_cipher_rfc($c);
        my $alias= "-"; #get_cipher_suitealias($c); # =~ m/^\s*$/) ? "-" : "*";
        printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
               $key, $hex, $ssl, $keyx, $auth, $enc, $bits, $mac, $sec, $name);
        $err{'key'}++   if ($key  eq "-");
        $err{'sec'}++   if ($sec  ne "*");
        $err{'name'}++  if ($name ne "*");
        $err{'rfc'}++   if ($rfc  ne "*");
        $err{'desc'}++  if ($desc ne "*");
    }
    printf("=%s+%s+%s\n", "-"x14, "-"x15, "-------+"x8 );
    printf("=%14s\t%15s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
           "key", "hex", "ssl", "keyx", "auth", "enc", "bits", "mac", "sec", "name");
    printf("= %s ciphers\n", $cnt);
    return;
} # _yeast_ciphers_show

sub _yeast_ciphers          { # TODO: obsolete when ciphers defined in OSaft/Cipher.pm
    printf("#%s:\n", (caller(0))[3]);
    print "
=== list of ciphers ===
=

";
    return;
} # _yeast_ciphers

sub _yeast_cipher           { # TODO: obsolete when ciphers defined in OSaft/Cipher.pm
    printf("#%s:\n", (caller(0))[3]);
    print "
=== print internal data structures for a cipher ===

";
# TODO: %ciphers %cipher_names
    return;
}

sub _yeast_targets          {
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
    my $arg = " (does not exist)";
    ## no critic qw(Variables::ProhibitPackageVars); they are intended here
    if (-f $cfg{'RC-FILE'}) { $arg = " (exists)"; }
    _yeast("!!Hint: use --trace=2  to see Net::SSLinfo variables") if (2 > $cfg{'trace'});
    _yeast("!!Hint: use --trace=2  to see external commands")      if (2 > $cfg{'trace'});
    _yeast("!!Hint: use --trace=3  to see full %cfg")              if (3 > $cfg{'trace'});
    _ynull();
    _yeast("#") if (3 > $cfg{'trace'});
    _yline("");
    _yTRAC("$0", $mainsid);     # $0 is same as $ARG0
    _yTRAC("_yeast_init::SID", $SID_dbx) if (2 > $cfg{'trace'});
    _yTRAC("::osaft",  $osaft::VERSION);
    _yTRAC("Net::SSLhello", $Net::SSLhello::VERSION) if defined($Net::SSLhello::VERSION);
    _yTRAC("Net::SSLinfo",  $Net::SSLinfo::VERSION);
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
    _yTRAC("RC-FILE", $cfg{'RC-FILE'} . $arg);
    _yTRAC("--rc",    ((grep{/(?:--rc)$/i}     @ARGV) > 0)? 1 : 0);
    _yTRAC("--no-rc", ((grep{/(?:--no.?rc)$/i} @ARGV) > 0)? 1 : 0);
    _yTRAC("verbose", $cfg{'verbose'});
    _yTRAC("trace",  "$cfg{'trace'}, traceARG=$cfg{'traceARG'}, traceCMD=$cfg{'traceCMD'}, traceKEY=$cfg{'traceKEY'}, traceTIME=$cfg{'traceTIME'}");
    _yTRAC("time_absolut", $cfg{'time_absolut'});
    _yTRAC("dbx{file}", "[ " . join(", ", @{$dbx{'file'}}) . " ]");
    
    _yline(" %cmd {");
    if (2 > $cfg{'trace'}) {    # user friendly informations
        _yeast("          path= " . ___ARR(@{$cmd{'path'}}));
        _yeast("          libs= " . ___ARR(@{$cmd{'libs'}}));
        _yeast("     envlibvar= $cmd{'envlibvar'}");
        _yeast("       timeout= $cmd{'timeout'}");
        _yeast("       openssl= $cmd{'openssl'}");
    } else {    # full information
        foreach my $key (sort keys %cmd) { _yeast_trac(\%cmd, $key); }
    }
    _yeast("   use_openssl= $cmd{'extopenssl'}");   # user friendly always
    _yeast("use cipher from openssl= $cmd{'extciphers'}");  # dito.
    _yline(" %cmd }");
    if (1 < $cfg{'trace'}) {    # full information
        _yline(" complete %cfg {");
        foreach my $key (sort keys %cfg) {
            if ($key =~ m/(hints|openssl|ssleay|sslerror|sslhello|regex)$/) { # |data
                # FIXME: ugly data structures ... should be done by _yTRAC()
                _yeast("# - - - - HASH: $key = {");
                foreach my $k (sort keys %{$cfg{$key}}) {
                    if ($key =~ m/openssl/) {
                        _yTRAC($k, ___ARR(@{$cfg{$key}{$k}}));
                    } else {
                        _yTRAC($k, $cfg{$key}{$k});
                    };
                };
                _yeast("# - - - - HASH: $key }");
            } else {
                if ($key =~ m/targets/) {   # TODO: quick&dirty to get full data
                    foreach my $k (sort keys @{$cfg{$key}}) {
                        _yTRAC($key . "[$k]", ___ARR(@{$cfg{$key}[$k]}));
                    }
                } else {
                    _yeast_trac(\%cfg, $key);
                }
            }
        }
        _yline(" %cfg }");
        return;
    }
    # else  user friendly informations
    my $sni_name = $cfg{'sni_name'} || "<<undef>>"; # default is Perl's undef
    my $port     = $cfg{'port'} || "<<undef>>";     # default is Perl's undef
    _yline(" user-friendly cfg {");
    _yeast("      ca_depth= $cfg{'ca_depth'}") if defined $cfg{'ca_depth'};
    _yeast("       ca_path= $cfg{'ca_path'}")  if defined $cfg{'ca_path'};
    _yeast("       ca_file= $cfg{'ca_file'}")  if defined $cfg{'ca_file'};
    _yeast("       use_SNI= $Net::SSLinfo::use_SNI, force-sni=$cfg{'forcesni'}, sni_name=$sni_name");
    _yeast("  default port= $port (last specified)");
    _yeast_targets($cfg{'trace'}, $cfg{'prefix_verbose'}, @{$cfg{'targets'}});
    foreach my $key (qw(out_header format legacy showhost usehttp usedns usemx starttls starttls_delay slow_server_delay cipherrange)) {
        printf("%s%14s= %s\n", $cfg{'prefix_verbose'}, $key, $cfg{$key});
           # cannot use _yeast() 'cause of pretty printing
    }
    foreach my $key (qw(starttls_phase starttls_error)) {
        _yeast(      "$key= " . ___ARR(@{$cfg{$key}}));
    }
    _yeast("   SSL version= " . ___ARR(@{$cfg{'version'}}));
    printf("%s%14s= %s", $cfg{'prefix_verbose'}, "SSL versions", "[ ");
    printf("%s=%s ", $_, $cfg{$_}) foreach (@{$cfg{'versions'}});
    printf("]\n");
    _yeast(" special SSLv2= null-sslv2=$cfg{'nullssl2'}, ssl-lazy=$cfg{'ssl_lazy'}");
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
    if (0 < $cfg{'trace'}) {
        _yTRAC("cfg'exitcode'", $cfg{'exitcode'});
        _yTRAC("exit status",   (($cfg{'exitcode'}==0) ? 0 : $checks{'cnt_checks_no'}->{val}));
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
    return if (0 >= $cfg{'traceARG'});
    # using _y_ARG() may be a performance penulty, but it's trace anyway ...
    _yline(" ARGV {");
    _y_ARG("# summary of all arguments and options from command line");
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
sub _trace_cmd  { printf("%s %s->\n", $cfg{'prefix_trace'}, join(" ",@_)) if (0 < $cfg{'traceCMD'}); return; }

sub _vprintme   {
    #? write own version, command line arguments and date and time
    my ($s,$m,$h,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();
    return if (0 >= ($cfg{'verbose'} + $cfg{'trace'}));
    _yeast("$0 " . $mainsid);
    _yeast("$0 " . join(" ", @{$cfg{'ARGV'}}));
    if (defined $ENV{'OSAFT_MAKE'}) {   # SEE Make:OSAFT_MAKE (in Makefile.pod)
        _yeast("$0 dd.mm.yyyy HH:MM:SS (OSAFT_MAKE exists)");
    } else {
        _yeast("$0 " . sprintf("%02s.%02s.%s %02s:%02s:%02s", $mday, ($mon +1), ($year +1900), $h, $m, $s));
    }
    return;
} # _vprintme

# subs for formatted table
sub __data      { return (_is_member(shift, \@{$cfg{'commands'}}) > 0)   ? "*" : "?"; }
sub __data_title{ return sprintf("=%19s %s %s %s %s %s %s %s\n", @_); }
sub __data_head { return __data_title("key", "command", " %data  ", "%checks", "cmd-ch.", "short ", "intern ", " score"); }
sub __data_line { return sprintf("=%19s+%s+%s+%s+%s+%s+%s+%s\n", "-"x19, "-"x7, "-"x7, "-"x7, "-"x7, "-"x7, "-"x7, "-"x7); }
sub __data_data { return sprintf("%20s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", @_); }

# subs for fomated maps
sub __prot_option   {
    my $data;
    foreach my $key (sort keys %{$cfg{'openssl_option_map'}})  {
        $data .= __trac(\%{$cfg{'openssl_option_map'}}, $key) . "\n";
    }
    chomp  $data;   # remove last \n
    return $data;
} # __prot_option

sub __prot_version  {
    my $data;
    foreach my $key (sort keys %{$cfg{'openssl_version_map'}}) {
        $data .= __yeast(sprintf("%14s= ", $key) . sprintf("0x%04x (%d)", ${$cfg{'openssl_version_map'}}{$key}, ${$cfg{'openssl_version_map'}}{$key})) . "\n";
    }
    chomp  $data;   # remove last \n
    return $data;
} # __prot_version

sub _yeast_data {
    printf("#%s:\n", (caller(0))[3]);
    print "
=== internal data structure for commands ===
=
= This function prints a simple overview of all available commands and checks.
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
";

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
            push(@yeast, $key); # probaly internal command
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
            (_is_intern($key) > 0)                      ?   "I"  : " ",   # intern
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
    print "
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
";
    print "= internal or summary commands:\n=      " . join(" ", @yeast);
    print "\n";
    return;
} # _yeast_data

sub _yeast_prot {
    printf("#%s:\n", (caller(0))[3]);
    print "
=== internal data structure according protocols ===
=
= This function prints information about SSL/TLS protocols in various internal
= variables (hashes).
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
} # _yeast_prot

sub _yeast_grep {
    printf("#%s:\n", (caller(0))[3]);
    print "
=== list of internal functions in $cfg{'me'} ===

= function                      | description
=-------------------------------+------------------------------------------
";
    my $perlprog = 'sub p($$){printf("%-24s\t%s\n",@_);}
      ($F[0]=~/^#/)&&do{$_=~s/^\s*#\??/-/;p($s,$_)if($s ne "");$s="";};
      ($F[0] eq "sub")&&do{p($s,"")if($s ne "");$s=$F[1];}';
    system('perl', '-lane', "$perlprog", $0);   # quick&dirty
    return;
} # _yeast_grep

sub _yeast_test {
    #? dispatcher for internal tests, initiated with option --test-*
    my $arg = shift;
    _yeast($arg);
    osaft::test_regex()     if ('regex'     eq $arg);
    _yeast_grep()           if ('sub'       eq $arg);
    _yeast_data()           if ('data'      eq $arg);
    _yeast_prot()           if ('prot'      eq $arg);
    # TODO: some of following obsolete when ciphers defined in OSaft/Cipher.pm
    _yeast_ciphers()        if ('ciphers'   eq $arg);
    $arg =~ s/^ciphers?[._-]?//;    # allow --test-* and --test-cipher-*
    _yeast_ciphers_sorted() if ('sort'      eq $arg);
    _yeast_ciphers_show()   if ('show'      eq $arg);
    _yeast_ciphers_overview() if ('overview' eq $arg);
   #_yeast_ciphers_list()    if ('list'     eq $arg);
    if ('list'     eq $arg) {
        # FIXME: --test-ciphers is experimental
        # _yeast_ciphers_list() relies on some special $cfg{} settings
        $cfg{'verbose'} = 1;
        push(@{$cfg{'do'}},      'cipherraw');
        push(@{$cfg{'version'}}, 'TLSv1') if (0 > $#{$cfg{'version'}});
        _yeast_ciphers_list();
    }
    return;
} # _yeast_test

sub _main_dbx       {
    ## no critic qw(InputOutput::RequireEncodingWithUTF8Layer)
    #   see t/.perlcriticrc for detailed description of "no critic"
    my $arg = shift || "--help";
    binmode(STDOUT, ":unix:utf8");
    binmode(STDERR, ":unix:utf8");
    if ($arg =~ m/--?h(elp)?$/) {
        # printf("# %s %s\n", __PACKAGE__, $mainsid);  # FIXME: if it is a perl package
        printf("# %s %s\n", __FILE__, $SID_dbx);
        if (eval {require POD::Perldoc;}) {
            # pod2usage( -verbose => 1 )
            exec( Pod::Perldoc->run(args=>[$0]) );
        }
        if (qx(perldoc -V)) {   ## no critic qw(InputOutput::ProhibitBacktickOperators)
            # may return:  You need to install the perl-doc package to use this program.
            #exec "perldoc $0"; # scary ...
            printf("# no POD::Perldoc installed, please try:\n   perldoc $0\n");
        }
    }
    if ($arg =~ m/--(yeast|test)[_.-]?(.*)/) {
        $arg = "--test-$1";
        printf("#$0: direct testing not yet possible, please try:\n   o-saft.pl $arg\n");
        # TODO: _yeast_test($arg);
    }
    exit 0;
} # _main_dbx

sub o_saft_dbx_done {};     # dummy to check successful include

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

=item --test-ciphers-list

=item --test-ciphers-show

=item --test-ciphers-sort

=item --test-ciphers-overview

=item --test-regex

=item --test-data

=item --test-prot

=item --test-sub

=back


=head1 DESCRIPTION

Defines all function needed for trace and debug output in  L<o-saft.pl|o-saft.pl>.


=head1 METHODS

=head2 Functions defined herein

=over 4

=item _yeast_ciphers_list( )

=item _yeast_trac( )

=item _yeast_init( )

=item _yeast_exit( )

=item _yeast_args( )

=item _yeast( )

=item _y_ARG( ), _y_CMD( ), _yline( )

=item _vprintme( )

=item _v_print( ), _v2print( ), _v3print( ), _v4print( )

=item _trace( ), _trace1( ), _trace2( ), _trace_cmd( )

=back

=head2 Functions for internal testing; initiated with option  C<--test-*>

=over 4

=item _yeast_ciphers_list( )

=item _yeast_ciphers_sorted( )

=item _yeast_data( )

=item _yeast_prot( )

=item _yeast_grep( )

=item _yeast_test( )

=back

=head2 Variables which may be used herein

They must be defined as `our' in L<o-saft.pl|o-saft.pl>:

=over 4


=item $mainsid

=item %data

=item %cfg, i.e. trace, traceARG, traceCMD, traceKEY, time_absolut, verbose

=item %checks

=item %dbx

=item $time0

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


=head1 VERSION

1.111 2019/12/29

=head1 AUTHOR

13-nov-13 Achim Hoffmann

=cut

## PACKAGE }

#_____________________________________________________________________________
#_____________________________________________________________________ self __|

_main_dbx(@ARGV) if (not defined caller);

1;
