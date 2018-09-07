#!/usr/bin/perl
## PACKAGE {

#!# Copyright (c) Achim Hoffmann, sic[!]sec GmbH
#!# This  software is licensed under GPLv2. Please see o-saft.pl for details.

package main;   # ensure that main:: variables are used

## no critic qw(ValuesAndExpressions::ProhibitCommaSeparatedStatements)
# FIXME: We have a lot of comman separated statements to simplify the code.
#        This needs to be changed in future to keep Perl::Critic happy.
#        However, the code herein is just for our own documentation ...

## no critic qw(RegularExpressions::ProhibitCaptureWithoutTest)
# NOTE:  This often happens in comma separated statements, see above.
#        It may also happen after postfix statements.
#        Need to check regularily for this problem ...

## no critic qw(RegularExpressions::ProhibitComplexRegexes)
#        Yes, we have very complex regex here.

## no critic qw(RegularExpressions::RequireExtendedFormatting)
#        We believe that most RegEx are not too complex.

## no critic qw(InputOutput::RequireBriefOpen)
#        We always close our filehandles, Perl::Critic is too stupid to read
#        over 15 lines.

## no critic qw(Modules::ProhibitExcessMainComplexity)
#        It's the nature of translations to be complex, hence don't complain.
# NOTE:  This expception fails, Perl::Critic still complains (probably a bug there)

use strict;
use warnings;
use vars qw(%checks %data %text); ## no critic qw(Variables::ProhibitPackageVars)
# binmode(...); # inherited from parent

use osaft;
use OSaft::Doc::Data;

my  $man_SID= "@(#) o-saft-man.pm 1.244 18/09/07 21:14:42";
my  $parent = (caller(0))[1] || "O-Saft";# filename of parent, O-Saft if no parent
    $parent =~ s:.*/::;
    $parent =~ s:\\:/:g;                # necessary for Windows only
my  $ich    = (caller(1))[1];           # tricky to get filename of myself when called from BEGIN
    $ich    = "o-saft-man.pm" if (not defined $ich); # sometimes it's empty :-((
    $ich    =~ s:.*/::;
my  $version= "$man_SID";               # version of myself
    $version= _VERSION() if (defined &_VERSION); # or parent's if available
my  $cfg_header = 0;                    # we may be called from within parents BEGIN, hence no %cfg available
    $cfg_header = 1 if (0 < (grep{/^--header/} @ARGV));
my  @help   = OSaft::Doc::Data::get_markup("help.txt", $parent, $version);
local $\    = "";

#_____________________________________________________________________________
#_________________________________________________________ internal methods __|

sub _man_dbx    { my @txt=@_; print "#" . $ich . " CMD: " . join(' ', @txt, "\n") if (0 < (grep{/^--(?:v|trace.?CMD)/i} @ARGV)); return; } # similar to _y_CMD
    # When called from within parent's BEGIN{} section, options are not yet
    # parsed, and so not available in %cfg. Hence we use @ARGV to check for
    # options, which is not performant, but fast enough here.

sub _man_file_get   {
    #? get filename containing text for specified keyword
    my $typ = shift;
    return OSaft::Doc::Data::get_as_text('glossary.txt')    if ('abbr'  eq $typ);
    return OSaft::Doc::Data::get_as_text('links.txt')       if ('links' eq $typ);
    return OSaft::Doc::Data::get_as_text('rfc.txt')         if ('rfc'   eq $typ);
    return '';
} # _man_file_get

sub _man_http_head  {
    #? print HTTP headers (for CGI mode)
    return if (0 >= (grep{/--cgi/} @ARGV));
    # checking @ARGV for --cgi is ok, as this option is for simulating
    # CGI mode only.
    # When called from o-saft.cgi, HTTP headers are already written.
    print "X-Cite: Perl is a mess. But that's okay, because the problem space is also a mess. Larry Wall\r\n";
    print "Content-type: text/html; charset=utf-8\r\n";
    print "\r\n";
    return;
} # _man_http_head

sub _man_html_head  {
    #? print footer of HTML page
    # SEE HTML:JavaScript
    my $version = shift;
    _man_dbx("_man_html_head($version) ...");
    print << 'EoHTML';
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title> . :  O - S a f t  &#151;  OWASP - SSL advanced forensic tool : . </title>
<script>
function $(id){return document.getElementById(id);}                            
function d(id){return $(id).style;}
function toggle_checked(id){id=$(id);id.checked=(id.checked=='false')?'true':'false';;}
function toggle_display(id){id.display=(id.display=='none')?'block':'none';}
function osaft_buttons(){
        var buttons = ['+quick', '+check', '+cipher', '+cipherall', '+info', '+protocols', '+vulns' ];
        var table   = $('osaft_buttons');
        for (var b in buttons) {
                // <input type=submit name="--cmd" value="+check" ><div class=q
                // id='c+check'></div><br>
                tr = document.createElement('TR');
                td = document.createElement('TD');
                cc = document.createElement('INPUT');
                cc.type   = 'submit'; cc.name='--cmd'; cc.value=buttons[b];     
                cc.title  = 'execute: o-saft.pl ' + buttons[b];
                //cc.target = 'o-saft.pl_' + buttons[b];
                td.appendChild(cc);
                tr.appendChild(td);
                td = document.createElement('TD');
                td.setAttribute('class', 'q');
                td.id='q' + buttons[b];
                tr.appendChild(td);
                table.appendChild(tr);
        }
}
function osaft_commands(){                                                                  
/* get help texts from generated HTML for commands and add it to command
 * button (generated by osaft_buttons, see above) of cgi-GUI
 * existing  tag of text paragraph containing help text has  id=h+cmd
 * generated tag of  quick button  containing help text has  id=q+cmd
 */
	osaft_buttons();                                                                           
        var arr = document.getElementsByTagName('p');                          
        for (var p=0; p<arr.length; p++) {                                     
            if (/^h./.test(arr[p].id)===true) {                                
                var id = arr[p].id.replace(/^h/, 'q');                         
		if ($(id) != undefined) {
			// button exists, add help text
                	$(id).innerHTML = $(arr[p].id).innerHTML;                      
            	}                                                                  
            }                                                                  
        }                                                                      
}
function osaft_options(){                                                                  
/* get help texts from generated HTML for options and add it to option
 * checkbox of cgi-GUI (actually add it to the parents title tag)
 * existing  tag of text paragraph containing help text has  id=h--OPT
 * generated tag of quick checkbox containing help text has  id=q--OPT
 */
        var arr = document.getElementsByTagName('p');                          
        for (var p=0; p<arr.length; p++) {                                     
            if (/^h./.test(arr[p].id)===true) {                                
                var id = arr[p].id.replace(/^h/, 'q');                         
		// TODO: *ssl and *tls must use *SSL
                if ($(id) != undefined) {
                        obj = $(id).parentNode;
                        if (/^LABEL$/.test(obj.nodeName)===true) {
                                // checkbox exists, add help text to surrounding
                                // LABEL
                                obj.title = $(arr[p].id).innerHTML;                      
                        }
                }                                                                  
            }                                                                  
        }                                                                      
}
</script>
<style>
 .h             {margin-left:     1em;border:0px solid #fff;}
 .r             {float:right;}
 .b, div[class=h] > a, input[type=submit]{
    margin:0.1em;padding:0px 0.5em 0px 0.5em;
    text-decoration:none; font-weight:bold; color:#000;
    border:1px solid black; border-radius:2px; box-shadow:1px 1px 3px #666;
    background:linear-gradient(#fff, #ddd);}
 a[class="b r"]:hover, div[class=h] > a:hover {background:linear-gradient(#ddd, #fff);}
 .c             {font-size:12pt !important;border:1px none black;font-family:monospace;background-color:lightgray;}
 .q             {border:0px solid white;}
 p              {margin-left:     2em;margin-top:0;}
 td             {padding-left:    1em;}
 h2, h3, h4, h5 {margin-bottom: 0.2em;}
 body > h2      {margin-top:   -0.5em;padding:  1em; height:1.5em;background-color:black;color:white;}
 li             {margin-left:     2em;}
 div            {                     padding:0.5em; border:1px solid green;}
 div[class=c]   {margin-left:     4em;padding:0.1em; border:0px solid green;}
 div[class=n]   {                                    border:0px solid white;}
 form           {padding:1em;}
 span           {margin-bottom:   2em;font-size:120%;border:1px solid green;}
 label[class=i] {margin-right:    1em;min-width:8em; border:1px solid white;display:inline-block;}
 label:hover[class=i]{background-color:lightgray;border-bottom:1px solid green;}
 input          {margin-right:  0.5em;}
 input[type=submit]      {background:linear-gradient(gold, #ff0);min-width:8em;text-align:left;}
 input[type=submit]:hover{background:linear-gradient(#ff0, gold);}
 fieldset > p   {margin:           0px;padding:0.5em;background-color:#ffa;}
</style>
</head>
<body>
EoHTML
    print << "EoHTML";
 <h2 title=$version >O - S a f t &#160; &#151; &#160; OWASP - SSL advanced forensic tool</h2>
 <!-- also hides unwanted text before <body> tag -->
EoHTML
    return;
} # _man_html_head

sub _man_html_foot  {
    #? print footer of HTML page
    _man_dbx("_man_html_foot() ...");
    print << "EoHTML";
 <a href="https://github.com/OWASP/O-Saft/"   target=_github >Repository</a> &nbsp;
 <a href="https://github.com/OWASP/O-Saft/blob/master/o-saft.tgz" target=_tar class=b >Download (stable)</a><br>
 <a href="https://owasp.org/index.php/O-Saft" target=_owasp  >O-Saft Home</a>
 <hr><p><span style="display:none">&copy; sic[&#x2713;]sec GmbH, 2012 - 2017</span></p>
</body></html>
EoHTML
    return;
} # _man_html_foot

sub _man_html_chck  {
    #? same as _man_html_cbox() but without lable and only if passed parameter start with - or +
    my $n = shift || "";
    my $v = '';
    return '' if ($n !~ m/^(?:-|\+)+/);
    if ($n =~ m/^(?:\+)/) { # is command
        $v =  scalar((split(/\s+/,$n))[0]);
        $n =  '--cmd';
    } else { # is option
        $v =  '';
        $n =  scalar((split(/\s+/,$n))[0]);
    }
    return sprintf("<input type=checkbox name='%s' value='%s' >", $n, $v);
} # _man_html_chck
sub _man_name_ankor {
    my $n = shift;
    $n =~ s/,//g;  # remove comma
    #$n =~ s/\s/_/g;# replace spaces
    return $n;
} # _man_name_ankor
sub _man_html_ankor {
    #? print ankor tag for each word in given parameter
    my $n = shift;
    my $a = '';
    return sprintf('<a name="a%s"></a>', $n) if ($n !~ m/^[-\+]+/);
    foreach my $n (split(/[\s,]+/,$n)) {
        $a .= sprintf("<a name='a%s'></a>", _man_name_ankor($n));
    }
    return $a;
} # _man_html_ankor
#sub _man_html_cbox($) { my $key = shift; return sprintf("%8s--%-10s<input type=checkbox name=%-12s value='' >&#160;\n", "", $key, '"--' . $key . '"'); }
sub _man_html_cbox  {
    #? checkbox with clickable label and hover highlight
    my $key = shift;
       $key = '--' . $key;
    my $id  = '"q'  . $key . '"';
    return sprintf("%8s<label class=i for=%-12s><input type=checkbox id=%-12s name=%-12s value='' >%s</label>&#160;&#160;\n",
        "", $id, $id, $id, $key);
}
sub _man_html_span  { my $key = shift; return sprintf("%8s<span>%s</span><br>\n", "", $key); }
sub _man_html_cmd   { my $key = shift; return sprintf("%9s+%-10s<input  type=text     name=%-12s size=8 >\n", "", "", '"--' . $key . '"'); }
sub _man_html_go    { my $key = shift; return sprintf("%8s<input type=submit value='start' title='execute o-saft.pl with selected commands and options'/>\n", "") if ($key eq 'cgi'); return ""; }
    # SEE HTML:start

sub _man_html       {
    my $key = shift; # cgi or html
    my $anf = shift; # pattern where to start extraction
    my $end = shift; # pattern where to stop extraction
    my $h = 0;
    my $a = "";      # NOTE: Perl::Critic is scary, SEE Perlcritic:LocalVars
    my $p = "";      # for closing p Tag
    _man_dbx("_man_html($key, $anf, $end) ...");
    while ($_ = shift @help) {
        last if/^TODO/;
        $h=1 if/^=head1 $anf/;
        $h=0 if/^=head1 $end/;
        next if (0 == $h);                          # ignore "out of scope"
        m/^=head1 (.*)/   && do { printf("$p\n<h1>%s %s </h1>\n",_man_html_ankor($1),$1);$p="";next;};
        m/^=head2 (.*)/   && do { print _man_html_go($key); printf("%s\n<h3>%s %s </h3> <p onclick='toggle_display(this);return false;'>\n",_man_html_ankor($1),_man_html_chck($1),$1);next;};
        m/^=head3 (.*)/   && do { $a=$1; printf("%s\n<h4>%s %s </h4> <p onclick='toggle_display(this);return false;'>\n",_man_html_ankor($1),_man_html_chck($1),$1);next;}; ## no critic qw(Variables::RequireLocalizedPunctuationVars)
        m/^\s*S&([^&]*)&/ && do { print "<div class=c >$1</div>\n"; next; }; # code or example line
        s!'([^']*)'!<span class=c >$1</span>!g;     # markup examples
        s!"([^"]*)"!<cite>$1</cite>!g;              # markup examples
        s!L&([^&]*)&!<i>$1</i>!g;                   # markup other references
        s!I&([^&]*)&!<a href="#a$1">$1</a>!g;       # markup commands and options
        s!X&([^&]*)&!<a href="#a$1">$1</a>!g;       # markup references inside help
        s!^\s+($parent .*)!<div class=c >$1</div>!; # example line
        m/^=item +\* (.*)/&& do { print "<li>$1</li>\n";next;}; # very lazy ...
        m/^=item +\*\* (.*)/  && do{ print "<li type=square style='margin-left:3em'>$1 </li>\n";next;};
        s/^(?:=[^ ]+ )//;                           # remove remaining markup
        # add paragraph for formatting, SEE HTML:p and HTML:JavaScript
        m/^\s*$/ && do { ## no critic qw(Variables::RequireLocalizedPunctuationVars)
                    $a = "id='h$a'" if ('' ne $a);
                    print "$p<p $a>";
                    $p = "</p>";
                    $a = '';
                }; # SEE Perlcritic:LocalVars
        print;
    }
    print "$p"; # if not empty, otherwise harmless
    return;
} # _man_html

sub _man_head       {   ## no critic qw(Subroutines::RequireArgUnpacking)
    #? print table header line (dashes)
    my $len1 = shift;   # this line triggers Perl::Critic, stupid :-/
    my @args = @_;      # .. hence "no critic" pragma in sub line
    _man_dbx("_man_head(..) ...");
    return if (1 > $cfg_header);
    my $len0 = $len1 - 1;
    printf("=%${len0}s | %s\n", @args);
    printf("=%s+%s\n", '-'x  $len1, '-'x60);
    return;
} # _man_head
sub _man_foot       {
    #? print table footer line (dashes)
    my $len1 = shift;   # expected length of first (left) string
    return if (1 > $cfg_header);
    printf("=%s+%s\n", '-'x $len1, '-'x60);
    return;
} # _man_foot
sub _man_opt        {
    #? print line in  "KEY - VALUE"  format
    my @args = @_;
    my $len  = 16;
       $len  = 1 if ($args[1] eq "="); # allign left for copy&paste
    printf("%${len}s%s%s\n", @args);
    return;
} # _man_opt
sub _man_arr        {
    my ($ssl, $sep, $dumm) = @_;
    my @all = ();
    push(@all, sprintf("0x%08X",$_)) foreach (@{$cfg{'cipherranges'}->{$ssl}});
    printf("%16s%s%s\n", $ssl, $sep, join(' ', @all));
    return;
} # _man_arr
sub _man_cfg        {
    #? print line in configuration format
    my ($typ, $key, $sep, $txt) = @_;
    $txt =  '"' . $txt . '"' if ($typ =~ m/^cfg/);
    $key =  "--$typ=$key"    if ($typ =~ m/^cfg/);
    _man_opt($key, $sep, $txt);
    return;
} # _man_cfg

sub _man_pod_item   {
    #? print line as POD =item
    my $line = shift;
    print "=over\n\n$line\n=back\n";
    return;
} # _man_pod_item

sub _man_usr_value  {
    #? return value of argument $_[0] from @{$cfg{'usr-args'}}
    my $key =  shift;
       $key =~ s/^(?:--|\+)//;  # strip leading chars
    my @arg =  '';              # key, value (Note that value is anything right to leftmost = )
    map({@arg = split(/=/, $_, 2) if /^$key/} @{$cfg{'usr-args'}}); # does not allow multiple $key in 'usr-args'
    return $arg[1];
} # _man_usr_value

sub _man_doc_opt    {
    #? print text from file $typ in  "KEY - VALUE"  format
    #  type is:   abbr, links, rfc
    #  format is: opt, POD
    my ($typ, $sep, $format) = @_;  # format is POD or opt
    my  $url  = '';
    my  @txt  = _man_file_get($typ);
    # OSaft::Doc::*::get()  returns one line for each term;  format is:
    #   term followd by TAB (aka \t) followed by description text
    foreach my $line (@txt) {
        chomp  $line;
        next if ($line =~ m/^\s*$/);
        next if ($line =~ m/^\s*#/);
        my ($key, $val) = split("\t", $line);
            $key =~ s/\s*$//;
        if ('rfc' eq $typ) {    # RFC is different, adapt $key and $val
            $url = $val if ($key eq "url"); # should be first line only
            $val = $val . "\n\t\t\t$url/html/rfc$key";
            $key = "RFC $key";
        }
        _man_opt($key, $sep, $val)          if ('opt' eq $format);
        _man_pod_item("$key $sep $val\n")   if ('POD' eq $format);
    }
    return;
} # _man_doc_opt

sub _man_doc_pod    {
    #? print text from file $typ in  POD  format
    my ($typ, $sep) = @_;
    my  @txt  = _man_file_get($typ);
    # print comment lines only, hence add # to each line
    my  $help = "@txt";
        $help =~ s/\n/\n#/g;
    print "# begin $typ\n\n";
    print "# =head1 $typ\n\n";
    print $help;
    #_man_doc_opt($typ, $sep, "POD");   # if real POD should be printed
    print "# end $typ\n";
    return;
} # _man_pod_pod
#_____________________________________________________________________________
#__________________________________________________________________ methods __|

sub man_table       {   ## no critic qw(Subroutines::ProhibitExcessComplexity)
    #? print data from hash in tabular form, $typ denotes hash
    #? header of table is not printed if $typ is cfg-*
    #  NOTE critic: McCabe 22 (tested 5/2016) is not that bad here ;-)
    my $typ = shift;
    my %types = (
        # typ        header left    separator  header right
        #-----------+---------------+-------+-------------------------------
        'score' => ["key",           " - ",  " SCORE\t# Description"],
        'regex' => ["key",           " - ",  " Regular Expressions used internally"],
        'ourstr'=> ["key",           " - ",  " Regular Expressions to match own output"],
        'abbr'  => ["Abbrevation",   " - ",  " Description"],
        'intern'=> ["Command",       "    ", " list of commands"],
        'compl' => ["Compliance",    " - ",  " Brief description of performed checks"],
        'range' => ["range name",    " - ",  " hex values in this range"],
        'rfc'   => ["Number",        " - ",  " RFC Title and URL"],
        'links' => ["Title",         " - ",  " URL"],
        'check' => ["key",           " - ",  " Label text"],
        'data'  => ["key",           " - ",  " Label text"],
        'hint'  => ["key",           " - ",  " Hint text"],
        'text'  => ["key",           " - ",  " text"],
    );
    my $txt = "";
    my $sep = "\t";
    if (defined $types{$typ}) { # defensive programming
       $sep = $types{$typ}->[1];
    } else {
       $sep = "=" if ($typ =~ m/(?:^cfg[_-]|[_-]cfg$)/);
            # the purpose of cfg_* is to print the results in a format so that
            # they can be used with copy&paste as command line arguments
            # simply change the separator to =  while other headers are unused
            # (because no header printed at all)
    }
    _man_dbx("man_table($typ) ...");
    _man_head(16, $types{$typ}->[0], $types{$typ}->[2]) if ($typ !~ m/^cfg/);

    # first only lists, which cannot be redefined with --cfg-*= (doesn't make sense)

    _man_doc_opt($typ, $sep, 'opt');    # abbr, rfc, links, ...

    if ($typ eq 'compl') { _man_opt($_, $sep, $cfg{'compliance'}->{$_})    foreach (sort keys %{$cfg{'compliance'}}); }

    if ($typ eq 'intern') {
        # first list command with all internal commands-*
        foreach my $key (sort keys %cfg) {
            next if ($key !~ m/^commands-(?:.*)/);
            _man_opt($key, $sep, "+" . join(' +', @{$cfg{$key}}));
        }
        foreach my $key (sort keys %cfg) {
            next if ($key !~ m/^cmd-(.*)/);
            _man_opt("cmd-" . $1, $sep, "+" . join(' +', @{$cfg{$key}}));
        }
    }

    # now all lists, which can be redefined with --cfg-*=
    # _man_cfg() prints different data for  --help=TYP and --help=TYP-cfg
    if ($typ =~ m/(hint|ourstr|range|regex)/) {
        my $list = $1;
           $list =~ s/^cfg[._-]?//;
           $list =~ s/[._-]?cfg$//;
           $list =  'hints' if ($list =~ m/hint/);  # the key in %cfg is 'hints'; 'hint' is different
           $list =  'cipherranges' if ($list =~ m/range/);
        # TODO: --cfg_range=* and --cfg-regex=*  are not yet implemented
        #       however, we can print it using --help=cfg-regex
        foreach my $key (sort keys %{$cfg{$list}}) {
            $txt =  $cfg{$list}->{$key};
            _man_cfg($typ, $key, $sep, $txt);
        }
    }
    if ($typ =~ m/score/) {
        foreach my $key (sort keys %checks) {
            $txt =  $checks{$key}->{score} . "\t# " . $checks{$key}->{txt};
            $txt =  $checks{$key}->{score} if ($typ =~ m/cfg/);
            _man_cfg($typ, $key, $sep, $txt);
        }
    }
    if ($typ =~ m/check/) {
        foreach my $key (sort keys %checks) {
            $txt =  $checks{$key}->{txt};
            _man_cfg($typ, $key, $sep, $txt);
        }
    }
    if ($typ =~ m/(?:data|info)/) {
        foreach my $key (sort keys %data) {
            $txt =  $data{$key}->{txt};
            _man_cfg($typ, $key, $sep, $txt);
        }
    }
    if ($typ =~ m/hint/) {
        foreach my $key (sort keys %{$cfg{'hint'}}) {
            $txt =  $cfg{'hints'}->{$key};
            _man_cfg($typ, $key, $sep, $txt);
        }
    }
    if ($typ =~ m/text/) {
        foreach my $key (sort keys %text) {
            next if ('' eq ref($text{$key})); # skip except string
            $txt =  $text{$key};
            $txt =~ s/(\n)/\\n/g;
            $txt =~ s/(\r)/\\r/g;
            $txt =~ s/(\t)/\\t/g;
            _man_cfg($typ, $key, $sep, $txt);
        }
    }
    if ($typ !~ m/cfg/) {
        _man_foot(16);
    } else {
        # additional message here is like a WARNING or Hint,
        # do not print it if any of them is disabled
        return if (($cfg{'warning'} + $cfg{'out_hint'}) < 2);
        print <<"EoHelp";
= Format is:  KEY=TEXT ; NL, CR and TAB are printed as \\n, \\r and \\t
= (Don't be confused about multiple  =  as they are part of  TEXT.)
= The string  @@  inside texts is used as placeholder.
= NOTE: " are not escaped!

EoHelp
    }
    return;
} # man_table

sub man_commands    {
    #? print commands and short description
    # data is extracted from $parents internal data structure
    my $skip = 1;
    my $fh   = undef;
    _man_dbx("man_commands($parent) ...");
    # first print general commands, manually crafted here
    # TODO needs to be computed, somehow ...
    print "\n";
    _man_head(15, "Command", "Description");
    print <<"EoHelp";
                  Commands for information about this tool
+dump             Dumps internal data for SSL connection and target certificate.
+exec             Internal command; should not be used directly.
+help             Complete documentation.
+list             Show all ciphers supported by this tool.
+libversion       Show version of openssl.
+quit             Show internal data and exit, used for debugging only.
+VERSION          Just show version and exit.
+version          Show version information for program and Perl modules.

                  Commands to check SSL details
+bsi              Various checks according BSI TR-02102-2 and TR-03116-4 compliance.
+check            Check the SSL connection for security issues.
+check_sni        Check for Server Name Indication (SNI) usage.
+ev               Various checks according certificate's extended Validation (EV).
+http             Perform HTTP checks.
+info             Overview of most important details of the SSL connection.
+info--v          More detailled overview.
+quick            Quick overview of checks.
+protocols        Check for protocols supported by target.
+s_client         Dump data retrieved from  "openssl s_client ..."  call.
+sizes            Check length, size and count of some values in the certificate.
+sni              Check for Server Name Indication (SNI) usage.
+sts              Various checks according STS HTTP header.
+vulns            Check for various vulnerabilities.

                  Commands to test ciphers provided by target
+cipher           Check target for ciphers (using libssl).
+cipher-dh        Check target for ciphers (using libssl), prints also DH parameter.
+cipherall        Check target for all possible ciphers (same format as +cipher).
+cipherraw        Check target for all possible ciphers (special format).
+cipher-default   Check target for (default) selected cipher for each protocol.
+cipher-null      Check if target accepts NULL ciphers.
+cipher-adh       Check if target accepts ciphers with anonymous key exchange.
+cipher-exp       Check if target accepts EXPORT ciphers.
+cipher-cbc       Check if target accepts CBC ciphers.
+cipher-des       Check if target accepts DES ciphers.
+cipher-rc4       Check if target accepts RC4 ciphers.
+cipher-edh       Check if target supports ephemeral ciphers.
+cipher-pfs       Check if target supports ciphers with PFS.
+cipher-strong    Check if target selects strongest cipher.
+cipher-selected  Selected cipher.

EoHelp

    if (open($fh, '<:encoding(UTF-8)', $0)) { # need full path for $parent file here
        while(<$fh>) {
            # find start of data structure
            # all structure look like:
            #    our %check_some = ( # description
            #          'key' => {... 'txt' => "description of value"},
            #    );
            # where we extract the description of the checked class from first
            # line and the command and its description from the data lines
            if (m/^(?:my|our)\s+%(?:check_(?:[a-z0-9_]+)|data)\s*=\s*\(\s*##*\s*(.*)/) {
                $skip = 0;
                print "\n                  Commands to show results of checked $1\n";
                next;
            }
            $skip = 1, next if (m/^\s*\)\s*;/); # find end of data structure
            next if (1 == $skip);
            next if (m/^\s*'(?:SSLv2|SSLv3|D?TLSv1|TLSv11|TLSv12|TLSv13)-/); # skip internal counter
            my $t   = "\t";
           #   $t  .= "\t" if (length($1) < 7);
            printf("+%-17s%s\n", $1, $2) if m/^\s+'([^']*)'.*"([^"]*)"/;
        }
        close($fh);
    }
    _man_foot(15);
    print "\n";
    return;
} # man_commands

sub man_alias       {
    #? print alias and short description (if available)
    #
    # Aliases are extracted from the source code. All lines handling aliases
    # for commands or options are marked with the pattern  # alias:
    # From these lines we extract the regex, the real option or command and
    # the comment.
    #
    #                 /------- regex -------\         /--- command ----\  /pattern\ /--- comment ---
    # Examples of lines to match:
    #    if ($arg eq  '--nosslnodataeqnocipher'){$arg='--nodatanocipher';} # alias:
    #    if ($arg =~ /^--ca(?:cert(?:ificate)?)$/i)  { $arg = '--cafile';} # alias: curl, openssl, wget, ...
    #    if ($arg =~ /^--cadirectory$/i)     { $arg = '--capath';        } # alias: curl, openssl, wget, ...
    #    if ($arg eq  '-c')                  { $arg = '--capath';        } # alias: ssldiagnose.exe
    #   #if ($arg eq  '--protocol')          { $arg = '--SSL';           } # alias: ssldiagnose.exe
    #
    print "\n";
    _man_head(27, "Alias (regex)         ", "command or option   # used by ...");
    my $fh   = undef;
    my $p    = '[._-]'; # regex for separators as used in o-saft.pl
    if (open($fh, '<:encoding(UTF-8)', $0)) { # need full path for $parent file here
        while(<$fh>) {
            next if (not m(# alias:));
            next if (not m|^\s*#?if[^/']*.([^/']+).[^/']+.([^/']+).[^#]*#\s*alias:\s*(.*)?|);
            my $commt =  $3;
            my $alias =  $2;
            my $regex =  $1;
            # simplify regex for better (human) readability
            $regex =~ s/^\^//;      # remove leading ^
            $regex =~ s/^\\//;      # remove leading \
            $regex =~ s/\$$//;      # remove trailing $
            $regex =~ s/\(\?:/(/g;  # remove ?: in all groups
            $regex =~ s/\$p\?/-/g;  # replace variable
            if (29 > length($regex)) {
                printf("%-29s%-21s# %s\n", $regex, $alias, $commt);
            } else {
                # pretty print if regex is to large for first column
                printf("%s\n", $regex);
                printf("%-29s%-21s# %s\n", "", $alias, $commt);
            }
        }
        close($fh);
    }
    _man_foot(27);
    print <<'EoHelp';
= Note for names in  Alias  column:
=   For option names  - or _ characters are not shown, they are stripped anyway.
=   For command names - or _ characters are also possible, but only - is shown.

EoHelp
    return;
} # man_alias

sub man_html        {
    #? print complete HTML page for o-saft.pl --help=gen-html
    #? recommended usage:   $0 --no-warning --no-header --help=gen-html
    # for concept and functionality of the generated page  SEE HTML:JavaScript
    _man_dbx("man_html() ...");
    _man_http_head();
    _man_html_head(STR_VERSION);
    _man_html('html', 'NAME', 'TODO');
    _man_html_foot();
    return;
} # man_html

sub man_pod         {
    #? print complete POD page for o-saft.pl --help=gen-pod
    #? recommended usage see at end of this sub
    _man_dbx("man_pod() ...");
    print <<'EoHelp';
#!/usr/bin/env perldoc
#?
# Generated by o-saft.pl .
# Unfortunatelly the format in @help is incomplete,  for example proper  =over
# and corresponding =back  paragraph is missing. It is mandatory arround =item
# paragraphs. However, to avoid tools complaining about that,  =over and =back
# are added to each  =item  to avoid error messages in the viewer tools.
# Hence the additional identations for text following the =item are missing.
# Tested viewers: podviewer, perldoc, pod2usage, tkpod

EoHelp
    print "=pod\n\n=encoding utf8\n\n"; # SEE POD:Syntax

    my $code  = 0;  # 1 if last printed line was `source code' format
    my $empty = 0;  # 1 if last printed line was empty
    while ($_ = shift @help) {          # @help already looks like POD
        last if m/^(?:=head[1] )?END\s+#/;# very last line in this file
        m/^$/ && do {  ## no critic qw(RegularExpressions::ProhibitFixedStringMatches)
            if (0 == $empty)  { print; $empty++; }  # empty line, but only one
            next;
        };
        s/^(\s*(?:o-saft\.|checkAll|yeast\.).*)/S&$1&/; # dirty hack; adjust with 14 spaces
        s/^ {1,13}//;                   # remove leftmost spaces (they are invalid for POD); 14 and more spaces indicate a line with code or example
        s/^S&\s*([^&]*)&/\t$1/ && do {  # code or example line
            print "\n" if (0 == ($empty + $code));
            print; $empty = 0; $code++; next;   # no more changes
        };
        $code = 0;
        s:['`]([^']*)':C<$1>:g;         # markup literal text; # dumm '
        s:X&([^&]*)&:L</$1>:g;          # markup references inside help
        s:L&([^&]*)&:L<$1|$1>:g;        # markup other references
        #s:L<[^(]*(\([^\)]*\)\>).*:>:g;  # POD does not like section in link
        s:I&([^&]*)&:I<$1>:g;           # markup commands and options
        s/^([A-Z., -]+)$/B<$1>/;        # bold
        s/^(=item)\s+(.*)/$1 $2/;       # squeeze spaces
        my $line = $_;
        m/^=/ && do {                   # paragraph line
            # each paragraph line must be surrounded by empty lines
            # =item paragraph must be inside =over .. =back
            print "\n"        if (0 == $empty);
            print "$line"     if $line =~ m/^=[hovbefpc].*/;# any POD keyword
            _man_pod_item "$line" if $line =~ m/^=item/;    # POD =item keyword
            print "\n";
            $empty = 1;
            next;
        };
        print "$line";
        $empty = 0;
    }
    print <<'EoHelp';
Generated with:

        o-saft.pl --no-warnings --no-header --help=gen-pod > o-saft.pod

EoHelp
    print "=cut\n\n";           # SEE POD:Syntax
    _man_doc_pod('abbr', "-");  # this is for woodoo, see below
    _man_doc_pod('rfc',  "-");  # this is for woodoo, see below
    print <<'EoHelp';

# begin woodoo

# Some documentation is plain text, which is  DATA  in Perl sources. As such,
# it  is  not detected as source,  not as comment,  and  not as documentation
# by most tools analyzing the source code.
# O-Saft's public user documentation is plain text stored in  separate files.
# The files are  usually also not counted as source.
# Unfortunately, some people solely believe in statistics generated by  magic
# tools. They use such statistics to measure for example code quality without
# looking themself at the code.
# Hence the purpose of this file is to provide real comment and documentation
# lines from our documentation in format of the used programming language.
# Hopefully, if these people read this, they change the workflow (means: they
# also review the source code) or adapt their conclusions having in mind that
# statistics can be manipulated in many ways. Here we go ...
#
# Disclaimer: No offence meant anyhow, neither against any analyzing tool nor
# against anyone using them. It is just a reminder to use the tools and their
# results in a wise manner. Measuring quality is more than just automatically
# generated statistics!

# end woodoo

EoHelp
    return;
} # man_pod

sub man_cgi         {
    #? print complete HTML page for o-saft.pl used as CGI
    #? recommended usage:      $0 --no-warning --no-header --help=gen-cgi
    #?    o-saft.cgi?--cgi=&--usr&--no-warning&--no-header=&--cmd=html
    #
    # <a href="$cgi?--cgi&--help=html"    target=_help >help (HTML format)</a>
    # previous link not generated because it prints multiple HTTP headers
    #
    # <from action= > and <a href= > values (link) must be specified using the
    # option  --usr-action=  at script start.
    #
    _man_dbx("man_cgi() ...");
    my $cgi = _man_usr_value('user-action') || _man_usr_value('usr-action') || "/cgi-bin/o-saft.cgi"; # get action from --usr-action= or set to default
    _man_http_head();
    _man_html_head(STR_VERSION);
print << "EoHTML";
 <div class=h ><b>Help:</b>
  <a href="$cgi?--cgi&--help"         target=_help title="open window with complete help"     >help</a>
  <a href="$cgi?--cgi&--help=command" target=_help title="open window with help for commands" >commands</a>
  <a href="$cgi?--cgi&--help=checks"  target=_help title="open window with help for checks"   >checks</a>
  <a href="$cgi?--cgi&--help=example" target=_help title="open window with examples"          >examples</a>
  <a href="$cgi?--cgi&--help=opt"     target=_help title="open window with help for options"  >options</a>
  <a href="$cgi?--cgi&--help=FAQ"     target=_help title="open window with FAQs"              >FAQ</a>
  <a href="$cgi?--cgi&--help=abbr"    target=_help title="open window with the glossar"       >Glossar</a>
  <a href="$cgi?--cgi&--help=todo"    target=_help title="open window with help for ToDO"     >ToDo</a><br>
 </div>
 <form action="$cgi" method="GET" target="cmd" >
  <noscript><div>JavaScript disabled. The buttons "Options", "Full GUI" and "Simple GUI" will not work.</div><br></noscript>
  <input  type=hidden name="--cgi" value="" >
  <fieldset>
    <p>
    Hostname: <input type=text name="--url"  size=40 title='hostname or hostname:port or URL' >
    <input  type=submit name="--cmd" title="execute: o-saft.pl +check ..." onclick='this.value="+check";' >
    </p>
    <table id="osaft_buttons">
    </table><br>
    <button onclick="toggle_display(d('a'));return false;" title="show options">Options</button>
    <div id=a >
        <button class=r onclick="toggle_display(d('a'));toggle_display(d('b'));return false;" title="switch to full GUI with all\ncommands and options and their description">Full GUI</button>
    <br>
      <div class=n>
EoHTML
        # Above HTML contains <div class=n> which contains checkboxes for some
        # options. These checkboxes are added in following  foreach loop.
        # Above HTML contains  <table id="osaft_buttons">  which contains the
        # quick buttons for some commands. These quick  buttons shoud get the
        # description from the later generated help text in this page,  hence
        # the buttons are not generated here but using  JavaScript at runtime
        # so that the corresponding help text  can be derived from the (HTML)
        # page itself. SEE HTML:JavaScript
    #foreach my $key (qw(cmd cmd cmd cmd)) { print _man_html_cmd($key); }
    foreach my $key (qw(no-sslv2 no-sslv3 no-tlsv1 no-tlsv11 no-tlsv12 no-tlsv13 BR
                     no-dns dns no-cert BR
                     no-sni sni   BR
                     no-http http BR
                     header  no-header  no-warnings BR
                     enabled disabled   BR
                     traceKEY traceCMD  trace v     BR
                 )) {
        if ('BR' eq $key) { print "        <br>\n"; next; }
        print _man_html_cbox($key);
    }
    print << "EoHTML";
      </div><!-- class=n -->
    </div><!-- id=a -->
    <div id=b >
        <button class=r onclick="d('a').display='block';d('b').display='none';return false;" title="switch to simple GUI\nwith most common options only">Simple GUI</button><br>
        <!-- not yet working properly                                                  
        <input type=text     name=--cmds size=55 title="type any command or option"/>/>
        -->
EoHTML

    _man_html('cgi', 'COMMANDS', 'LAZY'); # print help starting at COMMANDS
    print << "EoHTML";
</p>
        <input type=reset  value="clear" title="clear all settings"/>
    </div><!-- id=a -->
  </fieldset>
 </form>
 <hr>
 <script>
  osaft_commands("a");              // generate quick buttons
  osaft_options();                  // generate title for quick options
  d("a").display="none";            // hide
  d("b").display="none";            // hide
  toggle_checked("--header");       // want nice output
  toggle_checked("--enabled");      // avoid huge cipher lists
  toggle_checked("--no-tlsv13");    // most likely not yet implemented
</script>
EoHTML
    _man_html_foot();
    return;
} # man_cgi

sub man_wiki        {
    #? print documentation for o-saft.pl in mediawiki format (to be used at owasp.org)
    #? recommended usage:   $0 --no-warning --no-header --help=gen-wiki
    my $mode =  shift;
        # currently only mode=colon is implemented to print  :*  instead of *
        # Up to VERSION 15.12.15 list items * and ** where printed without
        # leading : (colon). Some versions of mediawiki did not support :*
        # so we can switch this behavior now.
    _man_dbx("man_wiki($mode) ...");
    my $key = "";

    # 1. generate wiki page header
    print <<'EoHelp';
==O-Saft==
This is O-Saft's documentation as you get with:
 o-saft.pl --help
<small>On Windows following must be used
 o-saft.pl --help --v
</small>

__TOC__ <!-- autonumbering is ugly here, but can only be switched of by changing MediaWiki:Common.css -->
<!-- position left is no good as the list is too big and then overlaps some texts
{|align=right
 |<div>__TOC__</div>
 |}
-->

[[Category:OWASP Project]]  [[Category:OWASP_Builders]]  [[Category:OWASP_Defenders]]  [[Category:OWASP_Tool]]  [[Category:SSL]]  [[Category:Test]]
----
EoHelp

    # 2. generate wiki page content
    #    extract from herein and convert POD syntax to mediawiki syntax
    while ($_ = shift @help) {
        last if/^=head1 TODO/;
        s/^=head1 (.*)/====$1====/;
        s/^=head2 (.*)/=====$1=====/;
        s/^=head3 (.*)/======$1======/;
        s/^=item (\*\* .*)/$1/;         # list item, second level
        s/^=item (\* .*)/$1/;           # list item, first level
        s/^=[^= ]+ *//;                 # remove remaining markup and leading spaces
        print, next if/^=/;             # no more changes in header lines
        s:['`]([^']*)':<code>$1</code>:g;  # markup examples # dumm '
        s/^S&([^&]*)&/  $1/ && do { print; next; }; # code or example line; no more changes
        s/X&([^&]*)&/[[#$1|$1]]/g;      # markup references inside help
        s/L&([^&]*)&/\'\'$1\'\'/g;      # markup other references
        s/I&([^&]*)&/\'\'$1\'\'/g;      # markup commands and options
        s/^ +//;                        # remove leftmost spaces (they are useless in wiki)
        if ('colon' eq $mode) {
            s/^([^=].*)/:$1/;           # ident all lines for better readability
        } else {
            s/^([^=*].*)/:$1/;          # ...
        }
        s/^:?\s*($parent)/  $1/;        # myself becomes wiki code line
        s/^:\s+$/\n/;                   # remove empty lines
        print;
    }

    # 3. generate wiki page footer
    print <<'EoHelp';
----
<small>
Content of this wiki page generated with:
 $parent --no-warning --no-header --help=gen-wiki
</small>

EoHelp
    return;
} # man_wiki

sub man_toc         {
    #? print help table of contents
    my $typ     = lc(shift) || "";      # || to avoid uninitialized value
    _man_dbx("man_toc() ..");
    foreach my $txt (grep{/^=head. /} @help) {  # note: @help is in POD format
        next if ($txt !~ m/^=head/);
        next if ($txt =~ m/^=head. *END/);  # skip last line
        if ($typ =~ m/cfg/) {
            $txt =~ s/^=head1 *(.*)/{print "--help=$1\n"}/e;
        } else {
            # print =head1 and =head2
            # just =head1 is lame, =head1 and =head2 and =head3 is too much
            $txt =~ s/^=head([12]) *(.*)/{print "  " x $1, $2,"\n"}/e; # use number from =head as ident
        }
    }
    return;
} # man_toc

sub man_help        {
    #? print complete user documentation for o-saft.pl as plain text (man-style)
    my $label   = lc(shift) || "";      # || to avoid uninitialized value
    my $anf     = uc($label);
    my $end     = "[A-Z]";
    _man_dbx("man_help($anf, $end) ...");
    # no special help, print full one or parts of it
    my $txt = join ('', @help);
	# = OSaft::Doc::Data::get("help.txt", $parent, $version);
    if (1 < (grep{/^--v/} @ARGV)) {     # with --v --v
	print OSaft::Doc::Data::get_egg("help.txt");
        return;
    }
    if ($label =~ m/^name/i)    { $end = "TODO";  }
    #$txt =~ s{.*?(=head. $anf.*?)\n=head. $end.*}{$1}ms;# grep all data
        # above terrible performance and unreliable, hence in peaces below
    $txt =~ s/.*?\n=head1 $anf//ms;
    $txt =~ s/\n=head1 $end.*//ms;      # grep all data
    $txt = "\n=head1 $anf" . $txt;
    $txt =~ s/\n=head2 ([^\n]*)/\n    $1/msg;
    $txt =~ s/\n=head3 ([^\n]*)/\n      $1/msg;
    $txt =~ s/\n=(?:[^ ]+ (?:\* )?)([^\n]*)/\n$1/msg;# remove inserted markup
    $txt =~ s/\nS&([^&]*)&/\n$1/g;
    $txt =~ s/[IX]&([^&]*)&/$1/g;       # internal links without markup
    $txt =~ s/L&([^&]*)&/"$1"/g;        # external links, must be last one
    if (0 < (grep{/^--v/} @ARGV)) {     # do not use $^O but our own option
        # some systems are tooo stupid to print strings > 32k, i.e. cmd.exe
        print "**WARNING: using workaround to print large strings.\n\n";
        print foreach split(//, $txt);  # print character by character :-((
    } else {
        print $txt;
    }
    if ($label =~ m/^todo/i)    {
        print "\n  NOT YET IMPLEMENTED\n";
        foreach my $label (sort keys %checks) {
            next if (0 >= _is_member($label, \@{$cfg{'commands-NOTYET'}}));
            print "        $label\t- " . $checks{$label}->{txt} . "\n";
        }
    }
    return;
} # man_help

sub src_grep        {
    #? search for given text in source file, then pretty print
    my $hlp = shift;
    print "\n";
    _man_head(14, "Option    ", "Description where program terminates");
    my $fh  = undef;
    if (open($fh, '<:encoding(UTF-8)', $0)) { # need full path for $parent file here
        while(<$fh>) {
            next if (m(^\s*#));
            next if (not m(_(?:EXIT|NEXT).*$hlp));
            my $opt     = $_;
            my $comment = $_;
            if ($opt =~ m/exit=/) {
                # line looks like: _yeast_EXIT("exit=BEGIN0 - BEGIN start");
                # or             : _yeast_NEXT("exit=HOST0 - host start");
                $opt =~ s/^[^"]*"/--/;    $opt =~ s/ - .*$//s;
                $comment =~ s/^[^-]*//; $comment =~ s/".*$//s;
            }
            printf("%-15s%s\n", $opt, $comment);
        }
        close($fh);
    }
    _man_foot(14);
    return;
} # src_grep

sub printhelp       {   ## no critic qw(Subroutines::ProhibitExcessComplexity)
    #? simple dispatcher for various help requests
    #  NOTE critic: as said: *this code is a simple dispatcher*, that's it
    my $hlp = shift;
    _man_dbx("printhelp($hlp) ...");
    # Note: some lower case strings are special
    man_help('NAME'),           return if ($hlp =~ /^$/);           ## no critic qw(RegularExpressions::ProhibitFixedStringMatches)
    man_help('TODO'),           return if ($hlp =~ /^todo$/i);      ## no critic qw(RegularExpressions::ProhibitFixedStringMatches)
    man_help('KNOWN PROBLEMS'), return if ($hlp =~ /^(err(?:or)?|warn(?:ing)?|problem)s?$/i);
    if ($hlp =~ /^faq/i) {
        man_help('KNOWN PROBLEMS');
        man_help('LIMITATIONS');
        return
    }
    man_help($hlp),             return if ($hlp =~ /^(?:CHECKS?|CUSTOM)$/); # not case-sensitive!
        # NOTE: bad design, as we have headlines in the documentation which
        #       are also used as spezial meaning (see below). In particular
        #       CHECKS  is a  headline for a section  in the documentation,
        #       while  checks  is used to print the labels of performed all
        #       checks. Workaround is to treat all-uppercase words as head-
        #       line of a section and anything else as special meaning.
        # However, note that  --help=chec  already behaves the  same way as
        # --help=CHECKS  while  --help=check  prints the labels. Means that
        # this special condition (match CHECKS) is just for commodity.
    man_toc($1),                return if ($hlp =~ /^((?:toc|content)(?:.cfg)?)/i);
    man_html(),                 return if ($hlp =~ /^(gen-)?html$/);
    man_wiki('colon'),          return if ($hlp =~ /^(gen-)?wiki$/);
    man_pod(),                  return if ($hlp =~ /^(gen-)?pod$/i);
    man_cgi(),                  return if ($hlp =~ /^(gen-)?cgi$/i);
        # Note: gen-cgi is called from within parent's BEGIN and hence
        # causes some   Use of uninitialized value within %cfg
        # when called as  gen-CGI  it will not be called from within
        # BEGIN and hence %cfg is defined and will not result in warnings
    man_alias(),                return if ($hlp =~ /^alias(es)?$/);
    man_commands(),             return if ($hlp =~ /^commands?$/);
    # anything below requires data defined in parent
    man_table('rfc'),           return if ($hlp =~ /^rfcs?$/);
    man_table('links'),         return if ($hlp =~ /^links?$/);
    man_table('abbr'),          return if ($hlp =~ /^(abbr|abk|glossary?)$/);
    man_table(lc($1)),          return if ($hlp =~ /^(intern|compl(?:iance)?)s?$/i);
    man_table(lc($1)),          return if ($hlp =~ /^(check|data|info|hint|text|range|regex|score|ourstr)s?$/i);
    man_table('cfg_'.lc($1)),   return if ($hlp =~ /^(check|data|info|hint|text|range|regex|score|ourstr)s?[_-]?cfg$/i);
    man_table('cfg_'.lc($1)),   return if ($hlp =~ /^cfg[_-]?(check|data|info|hint|text|range|regex|score|ourstr)s?$/i);
        # we allow:  text-cfg, text_cfg, cfg-text and cfg_text so that
        # we can simply switch from  --help=text  and/or  --cfg_text=*
    if ($hlp =~ /^cmds?$/i)     { # print program's commands
        print "# $parent commands:\t+"     . join(' +', @{$cfg{'commands'}});
        return;
    }
    if ($hlp =~ /^legacys?$/i)  { # print program's legacy options
        print "# $parent legacy values:\t" . join(' ',  @{$cfg{'legacys'}});
        return;
    }
    if ($hlp =~ /^help$/) {
	#my $hlp = OSaft::Doc::Data::get("help.txt", $parent, $version);
        my $txt  = "";
        foreach (@help) { $txt .= $_ if (m/Options for help and documentation/..m/Options for all commands/); };
            # TODO: quick&dirty match against to fixed strings (=head lines)
        $txt =~ s/^=head.//msg;
        $txt =~ s/Options for all commands.*.//msg;
        print "$txt";
        #man_help('Options for help and documentation');
        return;
    }
    if ($hlp =~ m/^opts?$/i)    { # print program's options
        my @txt  = grep{/^=head. (General|Option|--)/} @help;   # get options only
        foreach my $line (@txt) { $line =~ s/^=head. *//}       # remove leading markup
        my($end) = grep{$txt[$_] =~ /^Options vs./} 0..$#txt;   # find end of OPTIONS section
        print join('', "OPTIONS\n", splice(@txt, 0, $end));     # print anything before end
        return;
    }
    if ($hlp =~ m/^Tools$/i) {    # description for O-Saft tools
	print OSaft::Doc::Data::get("tools.txt", $parent, $version);
        return;
    }
    if ($hlp =~ m/^Program.?Code$/i) { # print Program Code description
	print OSaft::Doc::Data::get("coding.txt", $parent, $version);
        return;
    }
    src_grep("exit="),          return if ($hlp =~ /^exit$/i);
    # nothing matched so far, try to find special section and only print that
    _man_dbx("printhelp: " . uc($hlp));
    man_help(uc($hlp));
    return;
} # printhelp

sub _main           {
    ## no critic qw(InputOutput::RequireEncodingWithUTF8Layer)
    #   see .perlcritic for detailed description of "no critic"
    my $arg = shift;
    binmode(STDOUT, ":unix:utf8");
    binmode(STDERR, ":unix:utf8");
    if ($arg =~ m/--?h(elp)?$/) {
        if (eval {require POD::Perldoc;}) {
            # pod2usage( -verbose => 1 );
            exec( Pod::Perldoc->run(args=>[$0]) );
        }
        if (qx(perldoc -V)) {   ## no critic qw(InputOutput::ProhibitBacktickOperators)
            printf("# no POD::Perldoc installed, please try:\n  perldoc $0\n");   
        }
        exit 0;
    } else {
    printhelp($ARGV[0]);
    }
    exit 0;
} # _main

sub o_saft_man_done {};         # dummy to check successful include

#_____________________________________________________________________________
#_____________________________________________________ public documentation __|

=pod

=encoding utf8


=head1 NAME

o-saft-man.pm - perl module to handle O-Saft's documentation


=head1 DESCRIPTION

This module provides functionality to generate O-Saft's user documentation
in various formats. Supported formats are:

=over 2

=item * POD

=item * HTML

=item * mediawiki

=item * Plain Text

=back

Additionally various parts of the  documentation can be generated.  Please
see  L<METHODS>  below.


=head1 SYNOPSIS

=over 2

=item * require q{o-saft-man.pm}; printhelp($type);

=item * o-saft-man.pm [<$type>]

=back


=head1 METHODS

=over 2

=item * printhelp($type)

Public method for  all functionality.  The generated output format depends
on the $type parameter, which is a literal string, as follows:

=over 2

=item * pod     -> all documentation in POD format

=item * html    -> all documentation in HTML format

=item * wiki    -> all documentation in mediawiki format

=item * NAME    -> all documentation in plain text (man-style) format

=item * <empty>

=item * NAME    -> all documentation in plain text (man-style) format

=item * contents

=item * toc     -> table of contents for documentation as plain text

=item * help    -> list all options to get (help) information

=item * cgi     -> all documentation as HTML for CGI usage

=item * alias   -> list of all aliases for commands and options

=item * cmds    -> list of all commands (just the commands)

=item * command -> list of all commands with brief description

=item * opts    -> list of all options (just the options)

=item * options -> list of all options with full description

=item * legacy  -> list of legacy options

=item * checks  -> list of all SSL/TLS checks (each can be used as command)

=item * data    -> list of all SSL/TLS data values (each can be used as command)

=item * info    -> list of all SSL/TLS info values (each can be used as command)

=item * range   -> list of supported SSL/TLS cipher ranges (for +cipher)

=item * regex   -> list of most RegEx used internaly for SSL/TLS checks

=item * ourstr  -> list with RegEx matching special strings used in output

=item * tools   -> list of tools delivered with o-saft.pl

=item * abbr

=item * glossar -> list of abbrevations and terms according SSL/TLS

=item * links   -> list of links according SSL/TLS (incomplete)

=item * rfc     -> list of RFCs according SSL/TLS (incomplete)

=item * faq     -> lists known problems and limitations

=item * todo    -> show list of TODOs

=item * intern  -> some internal documentations

=item * Program.Code  -> description of coding style, conventions, etc.

=back

=back

If any other string is used,  'printhelp()'  extracts just the section of
the documention which is headed by that string.

NOTE that above list is also documented in ./OSaft/Doc/help.txt in section
"Options for help and documentation".
In a perfect world it would be extracted from there (or vice versa).


=head1 AUTHOR                                                                  
                                                                               
14-nov-14 Achim Hoffmann

=cut

## PACKAGE }

#_____________________________________________________________________________
#_____________________________________________________________________ self __|

_main(@ARGV) if (not defined caller);

1;

# SEE Note:Documentation (in o-saft.pl)

=pod

=head1 Annotations, Internal Notes

The annotations here are for internal documentation only.
For details about our annotations, please SEE  Annotations,  in o-saft.pl.


=head2 Perlcritic:LocalVars

Perl::Critic  complains that the variable $a should be localized in of the
code, this is wrong,  because it is exactly the purpose to find this value
(other settings) in other lines.
Hence  "no critic Variables::RequireLocalizedPunctuationVars"  needs to be
set in each line using $a.


=head2 POD:Syntax

The special POD keywords  =pod  and  =cut  cannot be used as  literal text
in particular in here documents, because (all?) most tools  extracting POD
from this file (for example perldoc) would be confused.
Hence these keywords need to be printed in a seperate statement.


=head2 HTML:p

For HTML format a paragraph tag '<p>' is used for all text blocks enclosed
in empty lines.  As RegEx are used to substitute the  markup text to HTML, 
empty paragraphs may be generated. This is harmless,  as browsers will not
render empty paragraphs.

Old-style '<p>' is used even we know that '<div>' is the modern standard.
This simplifies formating with CSS.


=head2 HTML:JavaScript

When generating the HTML page (wether plain HTML or CGI), each description
text for commands and options is placed in a paragraph ('<p>' tag),  which
has an 'id' attribute set to the name of the command or option.  This name
is prefixed with the letter 'h'. Example: the description of the '+cipher'
command is placed in following paragraph: <p id='h+cipher'> ... </p>.
These paragraphs are generated in  '_man_html()'.

This allows to extract the desciption text after generating the page using
JavaScript. See JavaScript function  'osaft_buttons()'.


=head2 HTML:start

The documenation in HTML format contains a "start" button at the bottom of
each toplevel section.  This should only be done when the page is used for
CGI (aka --help=cgi).

=cut
