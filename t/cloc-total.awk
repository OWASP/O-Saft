#!/usr/bin/awk -f
#?
#? NAME
#?      clock-total.awk   - reformat output of cloc and add column "total %"
#?
#? SYNOPSIS
#?      make cloc.csv       | clock-total.awk
#?      cloc --csv file ... | clock-total.awk
#?      cloc --csv file ... | awk -f clock-total.awk
#?
#? OPTIONS
#?      -v all=1    - prints all line not matching certificate data from input
#?                    default is to extract matching certificate data only
#?
#? DESCRIPTION
#?      Formats output of  "cloc --csv files ..."  same ways as  cloc  itself 
#?      and adds new column  "total %"  which contains the ratio of code lines
#?      per language.
#?
#? VERSION
#?      @(#) cloc-total.awk 1.1 %E 19:49:18
#?
#? AUTHOR
#?      12. January 2021 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

BEGIN {
	FS = ",";
	l  = 1;
}
/^ *$/  { next; }
/^files/{ next; }
/SUM/   { sum=$NF; }
{
	types[l++] = $2;
	files[$2]  = $1; # print files[$2];
	blank[$2]  = $3;
	commt[$2]  = $4;
	lines[$2]  = $5;
}
END {
	l = "#-------------+------+---------+-------+------------+-------------";
	print l;
	printf("# %-12s\t%5s\t%7s\t%7s\t%12s\t%s\n", "Language", "files", "total %", "blank %", "comment %", "code lines");
	print l;
	for (idx in types) {
		lang  = types[idx]
		total = sprintf("%2.2f", lines[lang] / sum * 100);
		if ("SUM" == lang) { print l;}
		printf("  %-12s\t%5s\t%7s\t%7s\t%12s\t%7s\n",
			lang, files[lang], total, blank[lang], commt[lang], lines[lang]);
	}
	print l;
}

