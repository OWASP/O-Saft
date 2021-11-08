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
#? DESCRIPTION
#?      Formats output of "cloc --csv files ..." same ways as  cloc itself. It
#?      adds the new column  "total %"  which contains the ratio of code lines
#?      per language.
#?
#? VERSION
#?      @(#) cloc-total.awk 1.4 21/11/08 13:15:02
#?
#? AUTHOR
#?      12. January 2021 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

BEGIN {
	FS = ",";
	l  = 1;
}
/^ *#/  { comments[c++] = $0; next; }   # comment lines from cloc
/^ *$/  { next; }       # empty lines from cloc
/^files/{ next; }       # header line from cloc
/SUM/   { cnt=$1; sum=$NF; }
{
	types[l++] = $2;
	files[$2]  = $1; # print files[$2];
	blank[$2]  = $3;
	commt[$2]  = $4;
	lines[$2]  = $5;
	if ($2 !~ /SUM/) { mycnt += $1; mysum += $NF; }
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
        if (mycnt != cnt || mysum != sum) {
		print "# mismatch calculated vs. reported numbers:"
		printf("#   calculated cnt %6d vs. reported cnt %6d\n", mycnt, cnt);
		printf("#   calculated sum %6d vs. reported SUM %6d\n", mysum, sum);
}
	if (0<c) { print "\n# Comments reported by cloc:"; }
	for (idx in comments) { print comments[idx]; }
}

