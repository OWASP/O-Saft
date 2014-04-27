#!/usr/bin/perl -w

=pod

=head1 NAME

o-saft-dbx.pm - module for tracing o-saft.pl

=head1 SYNOPSIS

require "o-saft-dbx.pm";

=head1 DESCRIPTION

Defines all function needed for trace and debug output in  L<o-saft.pl>.

=head2 Functions defined herein

=over 4

=item _yeast_init( )

=item _yeast_exit( )

=item _yeast_args( )

=item _yeast_data( )

=item _yeast_cipher( )

=item _yeast( )

=item _y_ARG( ), _y_CMD( )

=item _vprintme( )

=item _v_print( ), _v2print( ), _v3print( ), _v4print( )

=item _trace( ), _trace1( ), _trace2( ), _trace_1arr( )

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

    sub _yeast_init() {}

=head1 SPECIALS

If you want to do special debugging, you can define proper functions here.
They don't need to be defined in L<o-saft.pl> if they are used only here.
In that case simply call the function in C<_yeast_init> or C<_yeast_exit>
they are called at beginning and end of L<o-saft.pl>.
It's just important that  L<o-saft.pl>  was called with either the I<--v>
or any I<--trace*>  option, which then loads this file automatically.

=cut

my  $SID    = "@(#) o-saft-dbx.pm 1.10 14/04/27 17:50:31";

no warnings 'redefine';
   # must be herein, as most subroutines are already defined in main
   # warnings pragma is local to this file!
package main;   # ensure that main:: variables are used

# debug functions
sub _yeast($) { local $\ = "\n"; print "#" . $mename . ": " . $_[0]; }
sub _y_ARG    { local $\ = "\n"; print "#" . $mename . " ARG: " . join(" ", @_) if ($cfg{'traceARG'} > 0); }
sub _y_CMD    { local $\ = "\n"; print "#" . $mename . " CMD: " . join(" ", @_) if ($cfg{'traceCMD'} > 0); }
sub _yeast_init() {
    if (($cfg{'trace'} + $cfg{'verbose'}) >  0){
        _yeast("       verbose= $cfg{'verbose'}");
        _yeast("         trace= $cfg{'trace'}, traceARG=$cfg{'traceARG'}, traceCMD=$cfg{'traceCMD'}, traceKEY=$cfg{'traceKEY'}");
        _yeast("#----------------------------------------------------{");
        _yeast("# " . join(", ", @dbxexe));
        _yeast("          path= " . join(" ", @{$cmd{'path'}}));
        _yeast("          libs= " . join(" ", @{$cmd{'libs'}}));
        _yeast("     envlibvar= $cmd{'envlibvar'}");
        _yeast("  cmd->timeout= $cmd{'timeout'}");
        _yeast("  cmd->openssl= $cmd{'openssl'}");
        _yeast("   use_openssl= $cmd{'extopenssl'}");
        _yeast("openssl cipher= $cmd{'extciphers'}");
        _yeast("#----------------------------------------------------}");
        _yeast("      ca_depth= $cfg{'ca_depth'}") if defined $cfg{'ca_depth'};
        _yeast("       ca_path= $cfg{'ca_path'}")  if defined $cfg{'ca_path'};
        _yeast("       ca_file= $cfg{'ca_file'}")  if defined $cfg{'ca_file'};
        _yeast("       use_SNI= $Net::SSLinfo::use_SNI");
        _yeast("       targets= @{$cfg{'hosts'}}");
        foreach $key (qw(port out_header format legacy usehttp)) {
            printf("#%s: %14s= %s\n", $mename, $key, $cfg{$key});
               # cannot use _yeast() 'cause of pretty printing
        }
        _yeast("       version= @{$cfg{'version'}}");
        _yeast("      commands= @{$cfg{'do'}}");
        _yeast("        cipher= @{$cfg{'cipher'}}");
        _yeast("");
    }
}
sub _yeast_exit() {
    _y_CMD("internal administration ..");
    _y_CMD("cfg'done'{");
    _y_CMD("  $_ : " . $cfg{'done'}->{$_}) foreach (keys %{$cfg{'done'}});
    _y_CMD("cfg'done'}");
}
sub _yeast_args() {
    _y_ARG("#####{ summary of all arguments and options from command line");
    _y_ARG("#####  and: "      . join(", ", @dbxfile));
    _y_ARG("collected hosts= " . join(" ",  @{$cfg{'hosts'}}));
    _y_ARG("processed  exec  arguments= ". join(" ", @dbxexe));
    _y_ARG("processed normal arguments= ". join(" ", @dbxarg));
    _y_ARG("processed config arguments= ". join(" ", map{"`".$_."'"} @dbxcfg)) if($cfg{'verbose'} > 0);
    _y_ARG("#####}");
}
sub _v_print  { local $\ = "\n"; print "# "     . join(" ", @_) if ($cfg{'verbose'} >  0); }
sub _v2print  { local $\ = "";   print "# "     . join(" ", @_) if ($cfg{'verbose'} == 2); } # must provide \n if wanted
sub _v3print  { local $\ = "\n"; print "# "     . join(" ", @_) if ($cfg{'verbose'} == 3); }
sub _v4print  { local $\ = "";   print "# "     . join(" ", @_) if ($cfg{'verbose'} == 4); }
sub _trace($) { print "#" . $mename . "::" . $_[0] if ($cfg{'trace'} > 0); }
sub _trace0($){ print "#" . $mename . "::"                 if ($cfg{'trace'} > 0); }
sub _trace1($){ print "#" . $mename . "::" . join(" ", @_) if ($cfg{'trace'} > 1); }
sub _trace2($){ print "#" . $mename . "::" . join(" ", @_) if ($cfg{'trace'} > 2); }
sub _trace3($){ print "#" . $mename . "::" . join(" ", @_) if ($cfg{'trace'} > 3); }
sub _trace_($){ local $\ = "";  print  " " . join(" ", @_) if ($cfg{'trace'} > 0); }
# if --trace-arg given
sub _trace_1arr($) { printf("#%s %s->\n", $mename, join(" ",@_))if ($cfg{'traceKEY'} > 0); }
sub _vprintme {
    my ($s,$m,$h,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();
    _v_print("$0 " . $VERSION);
    _v_print("$0 " . join(" ", @ARGV));
    _v_print("$0 " . sprintf("%02s.%02s.%s %02s:%02s:%02s", $mday, ($mon +1), ($year +1900), $h, $m, $s));
}

sub __data($) { (_is_member(shift, \@{$cfg{'commands'}}) > 0)   ? "*" : "?"; }
sub _yeast_data() {
    print "
=== _yeast_data: check internal data structure ===

  This function prints a simple overview of all available commands and checks.
  The purpose is to show if for each command from  %cfg{'commands'}  a proper
  key is defined  in  %data  and  %checks  and vice versa.
";
    my ($key, $old, $label, $value);
    my @yeast = ();     # list of potential internal, private commands
    printf("%20s %s %s %s %s %s %s %s\n", "key", "command", "intern ", "  data  ", "short ", "checks ", "cmd-ch.", " score");
    printf("%20s+%s+%s+%s+%s+%s+%s+%s\n", "-"x20, "-"x7, "-"x7, "-"x7, "-"x7, "-"x7, "-"x7, "-"x7);
    $old = "";
    foreach $key
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
        $cmd = " ";
	$cmd = "+" if (_is_member($key, \@{$cfg{'commands'}}) > 0);     # command available as is
        printf("%20s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", $key,
	    $cmd,
            (_is_intern($key) > 0)      ?          "I"  : " ",
            (defined $data{$key})       ? __data( $key) : " ",
            (defined $shorttexts{$key}) ?          "*"  : " ",
            (defined $checks{$key})     ?          "*"  : " ",
            (_is_member($key, \@{$org{'cmd-check'}}) > 0) ? "*"  : "!",
            (defined $checks{$key}->{score}) ? $checks{$key}->{score} : ".",
            );
    }
    printf("%20s+%s+%s+%s+%s+%s+%s+%s\n", "-"x20, "-"x7, "-"x7, "-"x7, "-"x7, "-"x7, "-"x7, "-"x7);
    print '
    +  command (key) present
    I  command is an internal command or alias
    *  key present
       key not present
    ?  key in %data present but missing in $cfg{commands}
    !  key in %cfg{cmd-check} present but missing in redefined %cfg{cmd-check}

    A shorttext should be available for each command and all data keys, except:
        cn_nosni, ext_*, valid-*

    Please check following keys, they skipped in table above due to
    ';
    print "    internal or summary commands:\n        " . join(" ", @yeast);
    print "\n";
}

sub _yeast_cipher() {
# ToDo: %ciphers %cipher_names
}

1;
