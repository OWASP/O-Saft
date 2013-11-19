#!/usr/bin/perl -w

=pod

=head1 NAME

o-saft-dbx.pm - module for tracing o-saft.pl

=head1 SYNOPSIS

require "o-saft-dbx.pm";

=head1 DESCRIPTION

Defines all function needed for trace and debug output in  L<o-saft.pl>.

=head2 Variables which may be used herein

They must be defined as `our' in L<o-saft.pl>:

=over 4

=item $VERSION

=item $me   $mename   $mepath

=item %cfg, i.e. trace, traceARG, traceCMD, traceKEY, verbose

=back

=cut

my  $SID    = "@(#) o-saft-dbx.pm 1.1 13/11/19 01:50:48";

no warnings 'redefine';
   # must be herein, as all subroutines are already defined in main
   # warnings pragma is local to this file!
package main;   # ensure that main:: variables are used

# debug functions
sub _yeast($) { local $\ = "\n"; print "#" . $mename . ": " . $_[0]; }
sub _y_ARG    { local $\ = "\n"; print "#" . $mename . " ARG: " . join(" ", @_) if ($cfg{'traceARG'} > 0); }
sub _y_CMD    { local $\ = "\n"; print "#" . $mename . " CMD: " . join(" ", @_) if ($cfg{'traceCMD'} > 0); }
sub _yeast_init() {
    if (($cfg{'trace'} + $cfg{'verbose'}) >  0){
        _yeast("      verbose= $cfg{'verbose'}");
        _yeast("        trace= $cfg{'trace'}, traceARG=$cfg{'traceARG'}, traceCMD=$cfg{'traceCMD'}, traceKEY=$cfg{'traceKEY'}");
        _yeast(" cmd->timeout= $cmd{'timeout'}");
        _yeast(" cmd->openssl= $cmd{'openssl'}");
        _yeast("  use_openssl= $cmd{'extopenssl'}");
        _yeast("openssl cipher= $cmd{'extciphers'}");
        _yeast("      use_SNI= $Net::SSLinfo::use_SNI");
        _yeast("      targets= " . join(" ", @{$cfg{'hosts'}}));
        foreach $key (qw(port format legacy openssl cipher usehttp)) {
            printf("#%s: %13s= %s\n", $mename, $key, $cfg{$key});
        }
        _yeast("      version= " . join(" ", @{$cfg{'version'}}));
        _yeast("     commands= " . join(" ", @{$cfg{'do'}}));
        _yeast("");
    }
}
sub _yeast_exit() {
    _y_CMD("internal administration ..");
    _y_CMD("cfg'done'{");
    _y_CMD("  $_ : " . $cfg{'done'}->{$_}) foreach (keys %{$cfg{'done'}});
    _y_CMD("cfg'done'}");
}
sub _v_print  { local $\ = "\n"; print "# "     . join(" ", @_) if ($cfg{'verbose'} >  0); }
sub _v2print  { local $\ = "";   print "# "     . join(" ", @_) if ($cfg{'verbose'} == 2); } # must provide \n if wanted
sub _v3print  { local $\ = "\n"; print "# "     . join(" ", @_) if ($cfg{'verbose'} == 3); }
sub _v4print  { local $\ = "";   print "# "     . join(" ", @_) if ($cfg{'verbose'} == 4); }
sub _trace($) { print "#" . $mename . "::" . $_[0] if ($cfg{'trace'} > 0); }
# if --trace-arg given
sub _trace_1key($) { printf("#[%-16s ",    join(" ",@_) . ']')  if ($cfg{'traceKEY'} > 0); }
sub _trace_1arr($) { printf("#%s %s->\n", $mename, join(" ",@_))if ($cfg{'traceKEY'} > 0); }
sub _vprintme {
    my ($s,$m,$h,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();
    _v_print("$0 " . $VERSION);
    _v_print("$0 " . join(" ", @ARGV));
    _v_print("$0 " . sprintf("%02s.%02s.%s %02s:%02s:%02s", $mday, ($mon +1), ($year +1900), $h, $m, $s));
}

1;
