#!/usr/bin/perl -a -n
#?
#? NAME
#?      symbol.pl           - replay yes by  ✔  and no by  ✘
#?
#? SYNOPSIS
#?      o-saft.pl +check ... | symbol.pl
#?      o-saft.pl +check ... | perl symbol.pl
#?
#? DESCRIPTION
#?      Replace  yes  and  no  values in output by   ✔  and  ✘ .
#?
#? VERSION
#?      @(#) symbol.pl 1.1 19/10/25 23:36:32
#?
#? AUTHOR
#?      19. October 2019 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

use strict;
use warnings;

my $hook  = "✔";
my $cross = "❌";  # or u2716 ✖ or u2718 ✘ or u274c ❌or u1cf5 ᳵ

s#(\s+)yes\s*$#$1$hook\n#;
s#:(\s+)no(\s*.*)$#$1$cross$2\n#;
print;
