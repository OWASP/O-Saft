#!/usr/bin/gawk
#?
#? NAME
#?      XML-attribut.awk  - formatting o-saft.pl's output as XML with values
#?
#? SYNOPSIS
#?      o-saft.pl ... | gawk -f XML-attribut.awk
#?
#? DESCRIPTION
#?      Formats all output as XML with label and value as tag values:
#?          <info><label>Common Name</label><value>*exacmle.tld</value></info>
#?
#? VERSION
#?      @(#) XML-value.awk 1.1 16/06/11 12:36:55
#?
#? AUTHOR
#?      06. June 2016 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

BEGIN { FS="\t";
	print "<infos xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:noNamespaceSchemaLocation=\"SSLResults.xsd\" >"
}
(NF>0) {
	gsub(/&/,"\\&amp;");
	gsub(/</,"\\&lt;");
	gsub(/>/,"\\&gt;");
}
/^\s*$/{ next; }
($1~/^[#=]/) { print "<! "$0" -->"; next; }
{	printf(" <info><label>%s</label><value>%s</value></info>\n", $1, $2); }
END {	print "</info>"; }

