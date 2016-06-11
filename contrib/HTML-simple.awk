#!/usr/bin/gawk
#?
#? NAME
#?      HTML-simple.awk  - formatting o-saft.pl's output as simple HTML table
#?
#? SYNOPSIS
#?      o-saft.pl ... | gawk -f HTML-simple.awk
#?
#? DESCRIPTION
#?      Formats all output as HTML with label and value in table lines.
#?          <tr><th>Common Name</th><td>example.tld</td></tr>
#?
#? VERSION
#?      @(#) HTML-simple.awk 1.1 16/06/11 12:36:47
#?
#? AUTHOR
#?      06. June 2016 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

BEGIN {	FS="\t"; print "<html><body><table>"; }
(NF>0){
	gsub(/&/,"\\&amp;");
	gsub(/"/,"\\&quot;");
	gsub(/</,"\\&lt;");
	gsub(/>/,"\\&gt;");
}
/^\s*$/{ next; }
($1~/^[#=]/) {print "<! "$0" -->";next}
{	printf(" <tr><th>%s</th><td>%s</td></tr>\n", $1, $2); }
END {	print "</table></body></html>" }

