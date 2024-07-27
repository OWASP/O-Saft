#!/usr/bin/gawk -f
#?
#? NAME
#?      XML-attribute.awk  - formatting o-saft.pl's output as XML with attributes
#?
#? SYNOPSIS
#?      o-saft.pl ... | XML-attribute.awk
#?      o-saft.pl ... | gawk -f XML-attribute.awk
#?
#? DESCRIPTION
#?      Formats all output as XML with label and value as tag attributes:
#?          <info id="42" label="Common Name" value="*exacmle.tld" />
#?
#? VERSION
#?      @(#) XML-attribute.awk 1.3 24/07/27 22:56:48
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
	gsub(/"/,"\\&quot;");
	gsub(/</,"\\&lt;");
	gsub(/>/,"\\&gt;");
}
/^\s*$/{ next; }
($1~/^[#=]/) {gsub(/--/,"-\\-"); print "<!-- "$0" -->";next}
{
	i++;
	printf(" <info id=\"%s\" label=\"%s\" value=\"%s\" />\n",i,$1,$2);
}
END { print "</infos>" }

