#!/usr/bin/gawk -f
#?
#? NAME
#?      HTML-table.awk  - formatting o-saft.pl's output as HTML with table
#?
#? SYNOPSIS
#?      o-saft.pl ... | HTML-table.awk
#?      o-saft.pl ... | HTML4-table.awk
#?      o-saft.pl ... | gawk -f HTML-table.awk
#?      o-saft.pl ... | gawk -f HTML4-table.awk
#?
#? DESCRIPTION
#?      Formats all output as HTML with label and value in table lines.
#?      One table for each section in output and colours for some values.
#?          <tr><th>Common Name</th><td>example.tld</td></tr>
#?      Uses HTML5's <aside> tag to show links to headers of the page fixed at
#?      top  right of the page.
#?
#?      To distinguish if HTML4 or HTML5 should be used, the name of this file
#?      will be used.  Roughly, if the name starts with HTML5, HTML5 output is
#?      generated. If it starts with HTML4, HTML4 output is generated. Default
#?      is HTML5, also if this file is named HTML-*.
#
# HACKER's INFO
#       Detection of  own scriptname is tricky.  It depends on the environment
#       like: operating system, calling shell, awk vs. gawk. Luckily we insist
#       on gawk (see shebang above),  hence only the operating system needs to
#       be considered, as the calling shell does not provide reliable values.
#       As first attempt, we rely that  /proc/self/cmdline  exits, if not, the
#       the default behaviour will be used.
#       The command line  as to be found in  /proc/self/cmdline  consist of at
#       least following 3 words:  /usr/bin/gawk -f scriptname
#       If called manually from within the shell using gawk, it may look like:
#           gawk -f scriptname other arguments
#       but can also be, like:
#           gawk -v other=arg -f scriptname other arguments
#       The detection here stricktly relys on the first usage,  means that the
#       scriptname must be the third argument.
#?
#? VERSION
#?      @(#) HTML-table.awk 1.10 23/04/15 11:29:46
#?
#? AUTHOR
#?      06. June 2016 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

BEGIN {	FS="\t";
	# detect own scriptname
	getline t < "/proc/self/cmdline"; split(t,a,"\0");
	#dbx# print " /proc/self/cmdline\t = "cmd[3]; # [3] wenn: gawk -f t.awk
	html = 5;   # default (fallback)
	if (a[3] ~ /HTML-/)  { html = 5; }
	if (a[3] ~ /HTML4-/) { html = 4; }
	if (a[3] ~ /HTML5-/) { html = 5; }
	aside = "aside";
	main  = "main";
	if (4 == html) {
		aside = "div";
		main  = "div";
	}
	class = "";
	idx   = 1;
	print "<!DOCTYPE html>";
	print "<!-- converted to HTML"html" by HTML-table.awk 1.10 -->";
	print "<html><head><meta charset=\"utf-8\"><style>";
	print " .aside         { border:1px solid black; position:fixed; top:0.5em; right:0.5em;background:white;}";
	print " .aside details { background:white;}";
	print " .aside summary { font-size:120%; padding:0px  0.5em 0px 0.5em; border-bottom:1px solid black;}";
	print " .aside div > a { display:block;  margin:0.3em 0.3em 0.3em 1em;}";
	print " h2    { font-size:200%}";
	print " h3    { font-size:150%}";
	print " table { border:1px solid black;}";
#	print " th,td { border-bottom: 1px solid #ddd; }";
	print " th    { min-width: 30em;text-align:right;padding-right:1em;}";
	print " tr:first-child {background-color: #ccc}";
	print " tr:nth-child(even) {background-color: #f2f2f2}";
	print " .red {background-color:#f00;} .pink{background-color:#d6d;} .blue{background-color:#aad;} .gray{background-color:#0f0;} .or{background-color:#f80;} .ye{background-color:#ff0;}";
	print "</style></head><body><h1>O-Saft results</h1>";
	printf(" <%s id=\"main\">\n  <table>",main);
}

(NF>0){
	gsub(/&/,"\\&amp;");
	gsub(/"/,"\\&quot;");
	gsub(/</,"\\&lt;");
	gsub(/>/,"\\&gt;");
}
/^\s*$/{ next; }
($1~/ reading/)           { next; }
($1~/^**ERROR/)           { class = "red";  }
($1~/^**WARN/)            { class = "pink"; }
($1~/^**HINT/)            { class = "blue"; }
($1~/^!!Hint/)            { class = "blue"; }
(0 < length(class))       { sub(/ /,"\t");   printf("   <tr><th>%s</th><td colspan=2><span class=\"%s\">%s</span></td></tr>\n", $1, class, $2); class=""; next; }
($3~/[Hh][Ii][Gg][Hh]/)   { $3  = sprintf("<span class=\"gray\">%s</span>", $3);  }
($3~/[Mm][Ee][Dd][Ii]/)   { $3  = sprintf("<span class=\"ye\">%s</span>",   $3);  }
($3~/[Ll][Oo][Ww]/)       { $3  = sprintf("<span class=\"or\">%s</span>",   $3);  }
($3~/[Ww][Ee][Aa][Kk]/)   { $3  = sprintf("<span class=\"red\">%s</span>",  $3);  }
($NF == "yes")            { $NF = sprintf("<span class=\"gray\">%s</span>", $NF); }
($NF ~ /^no/)             { $NF = sprintf("<span class=\"ye\">%s</span>",   $NF); }
($1~/^====/ && $NF~/====/){ gsub(/====/,""); printf("  </table>\n  <h2 id=\"h%s\">%s</h2>\n  <table>\n", idx,$0); heads[idx]=$0; idx++; next; }
($1~/^===/ && $NF~/===/)  { gsub(/===/, ""); printf("  </table>\n  <h3 id=\"h%s\">%s</h3>\n  <table>\n", idx,$0); heads[idx]=$0; idx++; next; }
($1~/^== /)               {                  printf("   <tr><th colspan=2>%s</th></tr>\n",    $0); next; }
($1~/^=/ && $0 ~/ipher/ && $0~/supported/)  { # some header lines in cipher list are special
        split($0,a,/[ 	]*/);printf("   <tr><th>%s</th><td>%s</td><td>%s</td></tr>\n", a[2], a[3], a[4]); next; }
($1~/^=/ && $0!~/----/)   { gsub(/^ *=/,""); printf("   <tr><th>%s</th><th>%s</th></tr>\n", $1, $2); next; }
($1~/^[#=]/) { print "<!-- "$0" -->"; next; }
(NF == 2)    { printf("   <tr><th>%s</th><td>%s</td></tr>\n", $1, $2); next; }
(NF == 3)    { printf("   <tr><th>%s</th><td>%s</td><td>%s</td></tr>\n", $1, $2, $3); next; }
{	print; }
END {
	printf("  </table>\n </%s>\n", main );
	printf(" <%s class=\"aside\">",aside);
	if (4 == html) {
		print " <b>Content</b>";
		end = "";
	} else {
		print " <details><summary>Content</summary>";
		end = "</details>";
	}
	printf(" <div>\n");
	for (h=1; h<idx; h++) { printf("  <a href=\"#h%s\">%s</a>\n", h, heads[h]); }
	printf(" </div>%s</%s>\n", end,aside);
	printf("</body></html>\n");
}

