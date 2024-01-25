#!/usr/bin/perl -a -n
#?
#? NAME
#?      symbol.pl           - replace yes by  ✔  and no by  ❌
#?
#? SYNOPSIS
#?      o-saft.pl +check ... | symbol.pl
#?      o-saft.pl +check ... | perl symbol.pl
#?
#? DESCRIPTION
#?      Replace  yes  and  no  values in output by   ✔  and  ❌ .
#?
# HACKER's INFO
#       In following matching lines the substitution takes place:
#           Text used as label:     yes
#           Text used as label:     no
#           Text used as label:     no (some other text)
#       where the value  "yes"  or  "no .*"  may be enclosed in ANSI characters.
#?
#? VERSION
#?      @(#) symbol.pl 1.3 22/04/20 08:37:13
#?
#? AUTHOR
#?      19. October 2019 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

use strict;
use warnings;

my $hook  = "✔";
my $cross = "❌";  # or u2716 ✖ or u2718 ✘ or u274c ❌or u1cf5 ᳵ
my $ansi  = qr/\033\[\d(?:;\d\d)m/; # matches:  ^[[0;32m  and  ^[[0m  and  ^[[1;33m

s/
    (\s+${ansi}?)yes(${ansi})?\s*$
 /
    {my $x=(defined $2)?$2:""; "$1$hook$x\n"}
    # $1 is always set, at least containing white spaces
    # $2 is only set when ANSI characters are used, hence the check with
    #    defined to avoid Perl's "Use of undefined variable ..."
 /xe;
s/
    (:\s+${ansi}?)no(\s+.*)$
 /
    {my $x=(defined $2)?$2:""; "$1$cross$x"}
    # according $1 and $2 see above
 /xe;
print;
