#!/usr/bin/perl -w

=pod

=head1 NAME

o-saft-usr.pm - module for o-saft.pl's user definable functions

=head1 SYNOPSIS

require "o-saft-usr.pm";

=head1 DESCRIPTION

Defines all function for user customization.

WARNING: this is not a perl module defined with `package', but uses:
    package main;
hence is is recommended that all variables and function use a unique
prefix like:
    usr_  or _usr_

=head2 Functions defined herein

=over 4

=item usr_pre_init( )

At beginning, right before initializing internal data.

=item usr_pre_file( )

At beginning, right after initializing internal data.

=item usr_pre_args( )

Right before reading command line arguments.  All internal structures
and variables are initialized, all external files are read (except
configuration files specified witj  I<--cfg_*=>  option.

=item usr_pre_exec( )

All command line arguments are read. Right before executing myself.
This function also handles following commands and then exits:

  +htmlcgi      - print HTML page to start o-saft.cgi
  +htmlhelp     - print documentation in HTML format
  +wikihelp     - print documentation in mediawiki format

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

=head1 VERSION

Call:  usr_version()

=cut

my  $usr_SID= "@(#) o-saft-usr.pm 1.6 14/07/27 16:30:50";

no warnings 'redefine';
   # must be herein, as most subroutines are already defined in main
   # warnings pragma is local to this file!
package main;   # ensure that main:: variables are used

sub _usr_dbx { _trace(join(" ", @_)); } # requires --v

# user functions
# -------------------------------------
# These functions are called in o-saft.pl

sub usr_version()   { return "14.07.25"; }

sub usr_pre_init()  {
    _usr_dbx("usr_pre_init ...");
};

sub usr_pre_file()  {
    _usr_dbx("usr_pre_file ...");
};

sub usr_pre_args()  {
    _usr_dbx("usr_pre_args ...");
};

sub usr_pre_exec()  {
    _usr_dbx("usr_pre_exec ...");
    # All arguments and options are parsed.
    # Unknown commands are not available with _is_do() but can be
    # searched for in cfg{'done'}->{'arg_cmds'} which allows users
    # to "create" and use their own commands without changing 
    # o-saft.pl itself. However, o-saft.pl will print a WARNING then.

    if (_is_member('gen-help', \@{$cfg{'done'}->{'arg_cmds'}}) > 0) {
        # Usage:  $0 --user +gen-html
        usr_printhelp();
        exit 0;
    }

    if (_is_member('gen-cgi', \@{$cfg{'done'}->{'arg_cmds'}}) > 0) {
        # Usage:  $0 --user +gen-cgi
        usr_printcgi();
        exit 0;
    }

    if (_is_member('gen-wiki', \@{$cfg{'done'}->{'arg_cmds'}}) > 0) {
        # Usage:  $0 --user +gen-wiki
        usr_printwiki();
        exit 0;
    }
};

sub usr_pre_cipher(){
    _usr_dbx("usr_pre_cipher ...");
};

sub usr_pre_main()  {
    _usr_dbx("usr_pre_main ...");
};

sub usr_pre_host()  {
    _usr_dbx("usr_pre_host ...");
};

sub usr_pre_info()  {
    _usr_dbx("usr_pre_info ...");
};

sub usr_pre_open()  {
    _usr_dbx("usr_pre_open ...");
    ###
    ### sample code for using your own socket
    ###
    #use IO::Socket;
    #$Net::SSLinfo::socket = IO::Socket::INET->new(PeerHost=>'localhost', PeerPort=>443, Proto=>'tcp') 
    #or die "**ERROR usr_pre_open socket(): $!\n";
};

sub usr_pre_cmds()  {
    _usr_dbx("usr_pre_cmds ...");
};

sub usr_pre_data()  {
    _usr_dbx("usr_pre_data ...");
};

sub usr_pre_print() {
    _usr_dbx("usr_pre_print ...");
};

sub usr_pre_next()  {
    _usr_dbx("usr_pre_next ...");
};

sub usr_pre_exit()  {
    _usr_dbx("usr_pre_exit ...");
};

# local functions
# -------------------------------------
sub _usr_http_head(){
    print "X-Cite: Perl is a mess. But that's okay, because the problem space is also a mess. Larry Wall\r\n";
    print "Content-type: text/plain; charset=utf-8\r\n";
    print "\r\n";
}
sub _usr_html_head(){
    print << "EoHTML";
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title> . :  O - S a f t  &#151;  OWASP SSL audit for testers : . </title>
<script>
function d(id){return document.getElementById(id).style;}
function t(id){id.display=(id.display=='none')?'block':'none';}
</script>
<style>
 .r{float:right;}
 .c{!font-size:12pt !important;border:1px none black;font-family:monospace;background-color:lightgray;}
 p{margin-left:2em;margin-top:0;}
 h2, h3, h4, h5{margin-bottom:0.2em;}
 h2{margin-top:-0.5em;padding:1em;height:1.5em;background-color:black;color:white;}
 li{margin-left:2em;}
 div{padding:0.5em;border:1px solid green;}
 form{padding:1em;}
 span{font-size:8pt;border:1px solid green;}
</style>
</head>
<body>
 <h2>O - S a f t &#160; &#151; &#160; OWASP SSL advanced forensic tool</h2><!-- hides unwanted text before <body> tag -->
EoHTML
}
sub _usr_html_foot(){
    print << "EoHTML";
 <a href="https://github.com/OWASP/O-Saft/"   target=_github >Repository</a> &nbsp;
 <a href="https://github.com/OWASP/O-Saft/blob/master/o-saft.tgz" target=_tar ><button value="" />Download (stable)</button></a><br>
 <a href="https://owasp.org/index.php/O-Saft" target=_owasp  >O-Saft Home</a>
 <hr><p><span>&copy; sic[!]sec GmbH, 2012 - 2014</span></p>
</body></html>
EoHTML
}

sub _usr_html_chck($){
    #? same as _usr_html_cbox() but without lable and only if passed parameter start with - or +
    my $n = shift || "";
    return "" if ($n !~ m/^(-|\+)+/);
    return sprintf("<input type=checkbox name='%s' value='' >&#160;", scalar((split(/\s+/,$n))[0]));
}
sub _usr_name_ankor($){
    my $n = shift;
    $n =~ s/,//g;  # remove comma
    #$n =~ s/\s/_/g;# replace spaces
    return $n;
}
sub _usr_html_ankor($){
    #? print ankor tag for each word in given parameter
    my $n = shift;
    my $a = "";
    return sprintf("<a name=\"a%s\"></a>", $n) if ($n !~ m/^(-|\+)+/);
    #foreach $n (split(/\s+/,$n)) {
    #    $n = _usr_name_ankor($n);
    #    $a .= sprintf("<a name='a%s'></a>", $n);
    #}
    return sprintf("<a name=\"a%s\"></a>", $n);
    return $a;
}
sub _usr_html_cbox($) { return sprintf("%8s--%-10s<input type=checkbox name=%-12s value='' >&#160;\n", "", $_[0], '"--' . $_[0] . '"'); }
sub _usr_html_text($) { return sprintf("%8s--%-10s<input type=text     name=%-12s size=8 >&#160;\n", "", $_[0], '"--' . $_[0] . '"'); }
sub _usr_html_span($) { return sprintf("%8s<span>%s</span><br>\n", "", join(", ", @{$cfg{$_[0]}})); }
sub _usr_html_cmd($)  { return sprintf("%9s+%-10s<input type=text     name=%-12s size=8 >&#160;\n", "", "", '"--' . $_[0] . '"'); }

sub _usr_html_br()    { return sprintf("        <br>\n"); }

sub _usr_get_html($$) {
    my $anf = shift; # pattern where to start extraction
    my $end = shift; # pattern where to stop extraction
    my $cmd = "";
    my $h = 0; $c = 0;
    if (open(FID, $0)) {
    while (<FID>) {
        next if/^=(pod|cut|over|back|for|encoding)/;
        $h=1 if/$anf/;
        $h=0 if/$end/;
        next if/^__DATA__/;
        m/^=begin .*/&& do{$c=1;};              # start of comment
        m/^=end /    && do{$c=0;next;};         # end of comment, don't print
        next if $c==1;                          # ignore comments
        next if $h==0;                          # ignore "out of scope"
        next if m/^\s*$/;                       # ignore empty lines
        m/^=head1\s*(.*)/ && do { printf("\n<h1>%s %s</h1>\n",_usr_html_ankor($1),$1);next;};
        m/^=head([23])\s*(.*)/ && do { $i=$1;$i+=1;printf("%s\n<h%s>%s %s</h%s><p onclick='t(this);return false;'>\n",_usr_html_ankor($2),$i,_usr_html_chck($2),$2,$i);next;};
        #s#B<([^>]*)>#<u>$1</u>#g;              # markup references inside help
        s#C<([^>]*)>#<span class=c >$1</span>#g;# markup examples
        s#L<([^>]*)>#"$1"#g;                    # markup other references
        s![BI]<([^>]*)>! <a href="#a$1">$1</a>!g; # markup commands and options
        s#\$0#o-saftp.pl#g;                     # my name
        m/^=item(?:\s\*)?(.*)/ && do { print "<li>$1</li>\n";next;};
        s!\s((?:\+|--)[^,\s"]*)[,\s]! <a href="#a$1">$1</a> !; # markup references inside help
        s!\s"((?:\+|--)[^"]*)"! <a href="#a$1">$1</a>!g;    # markup references inside help
        #s#^=item(?:\s\*)?(.*)#<li> $1#;    
        print;
    }
    close(FID);
    }
}

sub usr_printhelp() {
    #? print complete HTML page for o-saft.pl +gen-html
    #? recommended usage:   $0 --no-header --usr +gen-html
    _usr_dbx("usr_printhtml ...");
    _usr_http_head() if (grep(/^usr-cgi/, @{$cfg{'usr-args'}}) > 0);
    _usr_html_head();
    _usr_get_html('^__DATA__', '^TODO');
    _usr_html_foot();
} # usr_printhelp

sub usr_printcgi() {
    #? print complete HTML page for o-saft.pl used as CGI
    #? recommended usage:   $0 --no-header --usr +gen-cgi
    #?    o-saft.cgi?--cgi=&--usr&--no-header=&--cmd=html
    _usr_dbx("usr_printcgi ...");
    my $cgi = get_usr_value('user-action') || get_usr_value('usr-action') || "/cgi-bin/o-saft.cgi"; # get action from --usr-action= or set to default
    my $key = "";
    _usr_http_head() if (grep(/^usr-cgi/, @{$cfg{'usr-args'}}) > 0);
    _usr_html_head();
print << "EoHTML";
 <a href="$cgi?--cgi&--help" target=_help ><button value="" />help</button></a>&#160;&#160;
 <a href="$cgi?--cgi&--help=command" target=_help ><button value="" />commands</button></a>&#160;&#160;
 <a href="$cgi?--cgi&--help=checks"  target=_help ><button value="" />checks</button></a>&#160;&#160;
 <a href="$cgi?--cgi&--help=score"   target=_help ><button value="" />score</button></a>&#160;&#160;
 <a href="$cgi?--cgi&--help=regex"   target=_help ><button value="" />regex</button></a>&#160;&#160;
 <a href="$cgi?--cgi&--abbr" target=_help ><button value="" />Glossar</button></a>&#160;&#160;
 <a href="$cgi?--cgi&--todo" target=_help ><button value="" />ToDo</button></a><br>
 <form action="$cgi" method=GET >
  <input  type=hidden name="--cgi" value="" >
  <fieldset>
EoHTML

    print _usr_html_text('host');
    print _usr_html_text('port');
print << "EoHTML";
    <div id=a style="display:block;">
        <button class=r onclick="t(d('a'));t(d('b'));return false;">Full GUI</button><br>
EoHTML
    foreach $key (qw(cmd cmd cmd cmd)) { print _usr_html_cmd($key); }
    print _usr_html_br();
    print _usr_html_span('cmd-intern');
    foreach $key (qw(sslv3 tlsv1 tlsv11 tlsv12 tlsv13 sslv2null BR
                     no-sni sni no-http http BR
                     no-dns dns no-cert BR
                     no-openssl openssl force-openssl  BR
                     no-header  header  short showhost BR
                     enabled disabled BR
                     v v trace trace traceCMD traceKEY BR
                 )) {
        if ($key eq 'BR') { print _usr_html_br(); next; }
        print _usr_html_cbox($key);
    }
    foreach $key (qw(separator timeout legacy)) { print _usr_html_text($key); }
    print _usr_html_br();
    print _usr_html_span('legacys');
    print _usr_html_text("format");
    print _usr_html_span('formats');

## cmd-intern:
## cipher check dump check_sni exec help info info--v http quick list libversion sizes s_client version quit sigkey bsi ev cipherraw cn_nosni valid-years valid-months valid-days
## 
## aus POD:
## cipher check dump check_sni exec      info info--v http quick list libversion sizes s_client version quit        bsi ev cipherraw
## 
## +sni +sni_check todo abbr +abk sts +hsts sni constraints

    print << "EoHTML";
	<br>
    </div>
    <div id=b style="display:none;">
        <button class=r onclick="d('a').display='block';d('b').display='none';return false;">Simple GUI</button><br>
        <input type=text     name=--cmds size=55 />&#160;
EoHTML

    _usr_get_html("^=head1\\s*COMMANDS", '^=head1\\s*LAZY');
    print << "EoHTML";
</p>
    </div>
	<input type=submit value="go" />
  </fieldset>
 </form>
EoHTML
    _usr_html_foot();
} # usr_printcgi

sub usr_printwiki() {
    #? print documentation for o-saft.pl in mediawiki format (to be used at owasp.org)
    #? recommended usage:   $0 --no-header --usr +gen-wiki
    # ToDo: this is a simple approach!
    _usr_dbx("usr_printwiki ...");
    my $key = "";
    # 1. generate wiki page header
    print "
==O-Saft==
This is O-Saft's documentation as you get with:
 o-saft.pl --help

__TOC__
<!-- position left is no good as the list is too big and then overlaps some texts
{|align=right
 |<div>__TOC__</div>
 |}
-->
<headertabs /> 

[[Category:OWASP Project]]  [[Category:OWASP_Builders]] [[Category:OWASP_Defenders]]  [[Category:OWASP_Tool]]
----
";
    # 2. generate wiki page content
    #    extract from herein and convert POD syntax to mediawiki syntax
    my $h = 0;
    if (open(FID, $0)) {
    while (<FID>) {
        # following matches should be similar to those in _usr_get_html()
        $h=1 if/^__DATA__/;
        next if/^__DATA__/;
        next if/^=(pod|cut|over|back|for|encoding)/;
        m/^=begin .*/&& do{$h=0;};              # star of comment
        m/^=end /    && do{$h=1;next;};         # end of comment, don_t print
        next if $h==0;
        s/^=head1(.*)/====$1====/;              # header
        s/^=head2(.*)/=====$1=====/;            # ..
        s/^=head3(.*)/======$1======/;          # ..
        s/^=item(?:\s\*)?(.*)/* $1/;            # list item
        s/^(=[^\s=]*\s)//;                      # remove spaces
        s/B<([^>]*)>/[[#$1|$1]]/g;              # markup references inside help
        s#C<([^>]*)>#<code>$1</code>#g;         # markup examples
        s/I<([^>]*)>/\'\'$1\'\'/g;              # markup commands and options
        s/L<([^>]*)>/\'\'$1\'\'/g;              # markup other references
        print, next if/^=/;                     # no more changes in header lines
        s/"((?:\+|--)[^"]*)"/\'\'$1\'\'/g;      # markup commands and options
        s#"([^"]*)"#<code>$1</code>#g;          # markup commands and options enclosed in quotes
        s/^([^=*].*)/:$1/;                      # identent all lines for better readability
        s/^:\s+\$0/    o-saft.pl/;              # replace myself with real name
        s/^:( {9}[^ ])(.*)/$1$2/;               # exactly 9 spaces used to highlight line
        s/^:\s+$/\n/;                           # remove empty lines
        if (m/^:/) {                            # add internal wiki links; quick&dirty list here
            s/((?:DEBUG|RC|USER)-FILE)/ [[#$1|$1]]/g;
            s/(CONFIGURATION (?:FILE|OPTIONS))/ [[#$1|$1]]/g;
            s/(SCORING)/ [[#$1|$1]]/g;
        }
        print;
    }
}
    # 2. generate wiki page footer
    print "
----
<small>
Content of this wiki page generated with:
 o-saft.pl --help=wiki
</small>
";
} # usr_printwiki

1;
