#!/usr/bin/gawk
#?
#? NAME
#?      HTML-table.awk  - formatting o-saft.pl's output as HTML with table
#?
#? SYNOPSIS
#?      o-saft.pl ... | gawk -f HTML-table.awk
#?
#? DESCRIPTION
#?      Formats all output as HTML with label and value in table lines.
#?      One table for each section in output and colours for some values.
#?          <tr><th>Common Name</th><td>example.tld</td></tr>
#?
#? VERSION
#?      @(#) HTML-table.awk 1.1 16/06/11 12:36:47
#?
#? AUTHOR
#?      06. June 2016 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

BEGIN {	FS="\t";
	print "<!DOCTYPE html>";
	print "<html><head><meta charset=\"utf-8\"><style>";
	print " h2 { font-size:200%}";
	print " table { border:1px solid black;}";
#	print " th,td { border-bottom: 1px solid #ddd; }";
	print " th { min-width: 30em;text-align:right;padding-right:1em;}";
	print " tr:nth-child(even) {background-color: #f2f2f2}";
	print " .red {background-color:#f00;} .pink{background-color:#d0d;} .blu{background-color:#00d;} .gr{background-color:#0f0;} .or{background-color:#f80;} .ye{background-color:#ff0;}";
	print "</style></head><body><table>";
}

(NF>0){
	gsub(/&/,"\\&amp;");
	gsub(/"/,"\\&quot;");
	gsub(/</,"\\&lt;");
	gsub(/>/,"\\&gt;");
}
/^\s*$/{ next; }
($1~/ reading/) { next; }
($1~/^**ERROR/) { $0 = sprintf("<span class=\"red\">%s</span>", $0); }
($1~/^**HINT/)  { $0 = sprintf("<span class=\"blu\">%s</span>", $0); }
($1~/^**WARN/)  { $0 = sprintf("<span class=\"pink\">%s</span>", $0); }
($3~/[Hh][Ii][Gg][Hh]/)   { $3 = sprintf("<span class=\"gr\">%s</span>", $3); }
($3~/[Mm][Ee][Dd][Ii]/)   { $3 = sprintf("<span class=\"ye\">%s</span>", $3); }
($3~/[Ll][Oo][Ww]/)       { $3 = sprintf("<span class=\"or\">%s</span>", $3); }
($3~/[Ww][Ee][Aa][Kk]/)   { $3 = sprintf("<span class=\"red\">%s</span>", $3); }
($NF == "yes") { $NF = sprintf("<span class=\"gr\">%s</span>", $NF); }
($NF ~ /^no/)            { $NF = sprintf("<span class=\"ye\">%s</span>", $NF); }
($1~/^===/ && $NF~/===/)  { gsub(/===/,""); printf("</table><h2>%s</h2>\n<table>", $0); next; }
($1~/^== /)  { printf("<tr><th colspan=2>%s</th></tr>\n", $0); next; }
($1~/^[#=]/) { print "<! "$0" -->"; next; }
(NF == 2)    { printf(" <tr><th>%s</th><td>%s</td></tr>\n", $1, $2); }
(NF == 3)    { printf(" <tr><th>%s</th><td>%s</td><td>%s</td></tr>\n", $1, $2, $3); }
END {	print "</table></body></html>"; }

