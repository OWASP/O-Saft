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
#?       --t     do not check if all files are commited to repository
#?       --v     be a bit verbose
#?
#? DESCRIPTION
#?       Generate script, which contains (all) modules for O-Saft.
#?
#?       NOTE: this will not generate a bulletproof stand-alone script!
#?
#? VERSION
#?       @(#) gen_standalone.sh 1.6 18/03/26 11:16:01
#?
#? AUTHOR
#?      02-apr-16 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

dst=o-saft_standalone.pl
src=o-saft.pl
try=
sid=1

while [ $# -gt 0 ]; do
	case "$1" in
	 '-h' | '--h' | '--help')
		ich=${0##*/}
		\sed -ne "s/\$0/$ich/g" -e '/^#?/s/#?//p' $0
		exit 0
		;;
	 '-n' | '--n') try=echo; ;;
	 '-t' | '--t') sid=0   ; ;;
	 '-v' | '--v') set -x  ; ;;
	esac
	shift
done

o_saft="
	osaft.pm
	OSaft/error_handler.pm
	OSaft/Doc/Data.pm
	Net/SSLhello.pm
	Net/SSLinfo.pm
	o-saft-dbx.pm
	o-saft-usr.pm
	o-saft-man.pm
"

osaft_doc="
		OSaft/Doc/coding.txt
		OSaft/Doc/glossary.txt
		OSaft/Doc/help.txt
		OSaft/Doc/links.txt
		OSaft/Doc/rfc.txt
"
#	OSaft/Doc/misc \


if [ $sid -eq 1 ]; then
	for f in $o_saft ; do
		# NOTE contribution to SCCS:  %I''%
		\egrep -q 'SID.*%I''%' $f \
	  	&& \echo "**ERROR: $f changes not commited; exit" \
	  	&& exit 2
	done
fi

\echo "# generate $dst ..."
\echo ""

$try \rm -rf $dst

[ "$try" = "echo" ] && dst=/dev/stdout

# general hints how to include:
# 1.  extract from o-saft.pl anything before line
## PACKAGES
#
# 2. add $osaft_standalone
#
# 3. include osaft.pm
#
# 4. include text from module file enclosed in  ## PACKAGE  scope  from all modules
#
# 5. add rest of o-saft.pl

(
  # 1.
  $try \perl -ne 'print if (m()..m(## PACKAGES ))' $src

  # 2.
  \echo ''
  \echo '$osaft_standalone = 1;'
  \echo ''

  # 4.
  # osaft.pm without brackets and no package
  f=osaft.pm
  \echo "# { # $f"
  $try \perl -ne 'print if (m(## PACKAGE {)..m(## PACKAGE })) and not m(package osaft;)' $f
  \echo "# } # $f"
  \echo ""

  ## TODO: OSaft/Doc/Data.pm
  f=OSaft/Doc/Data.pm
  \echo "{ # $f"
  $try \perl -ne 'print if (m(## PACKAGE {)..m(## PACKAGE }))' $f
  \echo "} # $f"
  \echo ""

  # TODO: o-saft-usr.pm  works, but not yet perfect
  f=o-saft-usr.pm
  \echo "{ # $f"
  $try \perl -ne 'print if (m(## PACKAGE {)..m(## PACKAGE }))' $f
  #$try \cat $f
  \echo "} # $f"
  \echo ""

  ## TODO: o-saft-dbx.pm  still with errors
  #f=o-saft-dbx.pm
  #\echo "{ # $f"
  #$try \perl -ne 'print if (m(## PACKAGE {)..m(## PACKAGE }))' $f
  #\echo "} # $f"
  #\echo ""

  ## TODO: o-saft-man  fails to include properly
  f=o-saft-man.pm
  \echo "{ # $f"
  $try \perl -ne 'print if (m(## PACKAGE {)..m(## PACKAGE })) and not m(use osaft;)' $f \
     | \grep -v  '^use OSaft::Doc::Data'
  \echo "} # $f"
  \echo ""

  f=OSaft/error_handler.pm
  \echo "{ # $f"
  #$try \perl -ne 'print if (m(## PACKAGE {)..m(## PACKAGE }))' $f
  $try \cat $f
  \echo "} # $f"
  \echo ""

  f=Net/SSLinfo.pm
  \echo "{ # $f"
  $try \perl -ne 'print if (m(## PACKAGE {)..m(## PACKAGE }))' $f
  \echo ""
  \echo 'my $_ssinfo_dum = $Net::SSLinfo::next_protos; # avoid Perl warning: "used only once: possible typo ..."'
  \echo "} # $f"
  \echo ""

  ## TODO: Net/SSLhello.pm  fails
	# Reasons: use of STR_HINT in _hint(); need: no strict 'subs'
  #f=Net/SSLhello.pm
  #\echo "{ # $f"
  #$try \perl -ne 'print if (m(## PACKAGE {)..m(## PACKAGE }))' $f \
  #   | \egrep -v  '^use (osaft|OSaft::error_handler)'
  #\echo "} # $f"
  #\echo ""

  # 5.
  \echo "package main;"
  $try \perl -ne 'print if (not m()..m(## PACKAGES)) and not m(use osaft;)' $src \
     | \egrep -v 'require (q.o-saft-man.pm|Net::SSLhello)'

) > $dst
$try \chmod 555 $dst
$try \ls    -la $dst
\echo "# $dst generated"

cat << EoDescription

	The generated stand-alone script misses following functionality:
	* Commands
		+cipherall
		+cipher-dh
	* Options
		--help
		--help=*
		--v
		--trace
		--trace-*
		--exit*
		--starttls
	Use of any of these commands or options will result in Perl compile
	errors like (unsorted):
		Use of uninitialized value ...
		Undefined subroutine ...
		Subroutine XXXX redefined at ...
		"our" variable XXXX redeclared at ...

	However, --help and --help=* will work if following files
	$osaft_doc
	are located in the same directory as  $dst .

	"perldoc $dst"  contains all POD of all included (module) files
	in unsorted order.

	For more details for a stand-alone script, please see:
		o-saft.pl --help=INSTALL

EoDescription

exit
