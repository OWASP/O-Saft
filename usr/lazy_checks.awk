#!/usr/bin/gawk -f
#?
#? NAME
#?      lazy_checks.awk  - filters some check results
#?
#? SYNOPSIS
#?      o-saft.pl +check ... | lazy_checks.awk
#?      o-saft.pl +check ... | gawk -f lazy_checks.awk
#?
#? DESCRIPTION
#?      Some checks from o-saft.pl's +check command report 'no (...)' as result
#?      and consequently increase the counter for total number of 'no' checks. 
#?      As some of these checks report 'no ()'  because of specific conditions,
#?      i.e. something is not applicapble (N/A), the total count for 'no' may
#?      sometimes be mis-leading.
#?
#?      This filter removes these results and adjusts the count.
#?
#?      Currently the following results are filtered:
#?          no (<<openssl ...
#?          no (<<N/A
#?
#? LIMITATIONS
#?      Pattern matching expects that label and value in the result line are
#?      separated by a :
#?
#? VERSION
#?      @(#) lazy_checks.awk 1.1 17/04/05 13:20:35
#?
#? AUTHOR
#?      06. April 2017 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

BEGIN {	FS=":"; }
/^\s*$/             { next; }
($2~/yes$/)         {y++;print;next}
($2~/no$/)          {n++;print;next}
($2~/<<NOT Y/)      {next}
($2~/<<N\/A/)       {next}
($2~/<<openssl /)   {next}
($2~/no /)          {n++;print;next}; # other 'no' results are printed
{print}
END {
	printf("Lazy count of check results 'no':\t%s\n", n)
	#printf("Lazy count of check results 'yes':\t%s\n",y); # same as before
}

