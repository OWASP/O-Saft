#!/usr/bin/gawk -f
#?
#? NAME
#?      HTML-table.awk  - formatting o-saft.pl's output as HTML with table
#?
#? SYNOPSIS
#?      o-saft.pl ... | HTML-table.awk
#?      o-saft.pl ... | gawk -f HTML-table.awk
#?
#? DESCRIPTION
#?      Formats all output as HTML with label and value in table lines.
#?      One table for each section in output and colours for some values.
#?          <tr><th>Common Name</th><td>example.tld</td></tr>
#?
#? VERSION
#?      @(#) HTML-table.awk 1.6 23/04/14 17:46:11
#?
#? AUTHOR
#?      06. June 2016 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

BEGIN {	FS="\t";
	print "<!DOCTYPE html>";
	print "<!-- converted to HTML by HTML-table.awk 1.6 -->";
	print "<html><head><meta charset=\"utf-8\"><style>";
	print " h2 { font-size:200%}";
	print " h3 { font-size:150%}";
	print " table { border:1px solid black;}";
#	print " th,td { border-bottom: 1px solid #ddd; }";
	print " th { min-width: 30em;text-align:right;padding-right:1em;}";
	print " tr:first-child {background-color: #ccc}";
	print " tr:nth-child(even) {background-color: #f2f2f2}";
	print " .red {background-color:#f00;} .pink{background-color:#d6d;} .blue{background-color:#aad;} .gray{background-color:#0f0;} .or{background-color:#f80;} .ye{background-color:#ff0;}";
	print "</style></head><body><h1>O-Saft results</h1>";
	print "<table>";
	class = "";
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
(0 < length(class))       { sub(/ /,"\t");printf(" <tr><th>%s</th><td colspan=2><span class=\"%s\">%s</span></td></tr>\n", $1, class, $2); class=""; next; }
($3~/[Hh][Ii][Gg][Hh]/)   { $3  = sprintf("<span class=\"gray\">%s</span>", $3);  }
($3~/[Mm][Ee][Dd][Ii]/)   { $3  = sprintf("<span class=\"ye\">%s</span>",   $3);  }
($3~/[Ll][Oo][Ww]/)       { $3  = sprintf("<span class=\"or\">%s</span>",   $3);  }
($3~/[Ww][Ee][Aa][Kk]/)   { $3  = sprintf("<span class=\"red\">%s</span>",  $3);  }
($NF == "yes")            { $NF = sprintf("<span class=\"gray\">%s</span>", $NF); }
($NF ~ /^no/)             { $NF = sprintf("<span class=\"ye\">%s</span>",   $NF); }
($1~/^====/ && $NF~/====/){ gsub(/====/,""); printf("</table>\n<hr><h2>%s</h2>\n<table>\n", $0); next; }
($1~/^===/ && $NF~/===/)  { gsub(/===/,"");  printf("</table>\n    <h3>%s</h3>\n<table>\n", $0); next; }
($1~/^== /)               {                  printf(" <tr><th colspan=2>%s</th></tr>\n",    $0); next; }
($1~/^=/ && $0 ~/ipher/ && $0~/supported/)  { # some header lines in cipher list are special
        split($0,a,/[ 	]*/);printf(" <tr><th>%s</th><td>%s</td><td>%s</td></tr>\n", a[2], a[3], a[4]); next; }
($1~/^=/ && $0!~/----/)   { gsub(/^ *=/,""); printf(" <tr><th>%s</th><th>%s</th></tr>",  $1, $2); next; }
($1~/^[#=]/) { print "<!-- "$0" -->"; next; }
(NF == 2)    { printf(" <tr><th>%s</th><td>%s</td></tr>\n", $1, $2); next; }
(NF == 3)    { printf(" <tr><th>%s</th><td>%s</td><td>%s</td></tr>\n", $1, $2, $3); next; }
{	print; }
END {	print "</table></body></html>"; }

