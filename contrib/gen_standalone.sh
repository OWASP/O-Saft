#!/bin/sh
#?
#? NAME
#?       $0 - generate o-saft_standalone.pl
#?
#? SYNOPSIS
#?       $0
#?
#? OPTIONS
#?       --h     got it
#?       --n     do not execute, just show what would be done
#?       --v     be a bit verbose
#?
#? DESCRIPTION
#?       Generate script, which contains all modules for O-Saft.
#?
#?       NOTE: this will not generate a bulletproof standalone script!
#?       To get a real standalone script, please see
#?           o-saft.pl --help=INSTALL
#?
#?       The generated script is mainly used to check the syntax, the  variable
#?       and i sub  declaraions.
#?       Running the generated script may report various perl warnings
#?           Subroutine XXXX redefined at ...
#?           "our" variable XXXX redeclared at ...
#?
#? VERSION
#?       @(#) gen_standalone.sh 1.3 16/04/10 02:54:52
#?
#? AUTHOR
#?      02-apr-16 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

dst=o-saft_standalone.pl
src=o-saft.pl
try=

while [ $# -gt 0 ]; do
	case "$1" in
	 '-h' | '--h' | '--help')
		ich=${0##*/}
		\sed -ne "s/\$0/$ich/g" -e '/^#?/s/#?//p' $0
		exit 0
		;;
	 '-n' | '--n') try=echo; ;;
	 '-v' | '--v') set -x  ; ;;
	esac
	shift
done

o_saft="\
	osaft.pm \
	Net/SSLhello.pm \
	Net/SSLinfo.pm \
	o-saft-dbx.pm \
	o-saft-usr.pm \
	o-saft-man.pm \
"

for f in $o_saft ; do
	\egrep -q 'SID.*1.3' $f \
	  && \echo "**ERROR: $f wird bearbeitet; exit" \
	  && exit 2
done

\echo "# generate $dst ..."
\echo ""

$try \rm -rf $dst

[ "$try" = "echo" ] && dst=/dev/stdout

(
  cat <<'EoT'
#!/usr/bin/perl -w

our $osaft_standalone = 1;
our $VERSION;
our $me     = $0; $me     =~ s#.*[/\\]##;
our $mepath = $0; $mepath =~ s#/[^/\\]*$##;
    $mepath = "./" if ($mepath eq $me);
our $mename = "yeast  ";
    $mename = "O-Saft " if ($me !~ /yeast/);
our (%cfg, %cmd, %data, %checks, %shorttexts, %org, %text);
our (@dbxexe, @dbxarg, @dbxcfg);

use constant {
    # dirty hask to avoid error
    STR_WARN  => "**WARNING: ",
    STR_ERROR => "**ERROR: ",
};


EoT

  for f in $o_saft ; do
	\echo "# $f {"
	$try \perl -ne 'print if m(## PACKAGE {)..m(## PACKAGE })' $f
	\echo "# $f }"
	\echo ""
  done

  $try \cat $src

) > $dst
$try \chmod 555 $dst

