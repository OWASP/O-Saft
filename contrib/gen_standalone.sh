#!/bin/sh
#?
#? NAME
#?       $0 - generate o-saft_standalone.pl
#?
#? SYNOPSIS
#?       $0
#?       $0 [OPTIONS] [output-file]
#?
#? OPTIONS
#?       --h     got it
#?       --n     do not execute, just show what would be done
#?       --t     do not check if all files are commited to repository
#?       --s     silent, do not print informations (for usage with Makefile)
#?       --v     be a bit verbose
#?
#? DESCRIPTION
#?       Generate script, which contains (all) modules for O-Saft.
#?       Prints on STDOUT if no [output-file] was specified.
#?
#?       NOTE: this will not generate a bulletproof stand-alone script!
#?
#? VERSION
#?       @(#)  2.4 22/11/13 22:24:11
#?
#? AUTHOR
#?      02-apr-16 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

dst=/dev/stdout # default STDOUT
src=o-saft.pl ; [ -f $src ] || src=../$src
try=
sid=1
info=1

while [ $# -gt 0 ]; do
	case "$1" in
	 '-h' | '--h' | '--help')
		ich=${0##*/}
		\sed -ne "s/\$0/$ich/g" -e '/^#?/s/#?//p' $0
		exit 0
		;;
	 '-n' | '--n') try=echo; ;;
	 '-t' | '--t') sid=0   ; ;;
	 '-s' | '--s') info=0  ; ;;
	 '-v' | '--v') set -x  ; ;;
	 *)            dst="$1"; ;;
	esac
	shift
done

if [ ! -e "$src" ]; then
  	\echo "**ERROR: '$src' does not exist; exit"
	[ "echo" = "$try" ] || exit 2
fi

_o_saft="
	osaft.pm
	OSaft/Text.pm
	OSaft/error_handler.pm
	OSaft/Doc/Data.pm
	Net/SSLhello.pm
	Net/SSLinfo.pm
	o-saft-dbx.pm
	o-saft-usr.pm
	o-saft-man.pm
	OSaft/Ciphers.pm
	OSaft/Data.pm
"
o_saft=""
for f in $_o_saft ; do
	[ -f $f ] || f=../$f    # quick&dirty if called in sub-directory
	o_saft="$o_saft $f"
done

_osaft_doc="
	OSaft/Doc/coding.txt
	OSaft/Doc/glossary.txt
	OSaft/Doc/help.txt
	OSaft/Doc/links.txt
	OSaft/Doc/rfc.txt
"
#	OSaft/Doc/misc \
osaft_doc=""
for f in $_osaft_doc ; do
	[ -f $f ] || f=../$f    # quick&dirty if called in sub-directory
	osaft_doc="$osaft_doc $f"
done


if [ $sid -eq 1 ]; then
	for f in $o_saft ; do
		# NOTE contribution to SCCS:  %I''%
		\egrep -q 'SID.*%I''%' $f \
	  	&& \echo "**ERROR: '$f' changes not commited; exit" \
	  	&& exit 2
	done
fi

if [ $info -eq 1 ]; then
	if [ "/dev/stdout" = "$dst" ]; then
		\echo "# generate file standalone.pl ..."
	else
		\echo "# generate $dst ..."
	fi
	\echo ""
fi

[ "/dev/stdout" != "$dst" ] && $try \rm -rf $dst

[ "$try" = "echo" ] && dst=/dev/stdout

# general workflow and hints how to include:
#
# 1.  extract from o-saft.pl anything before line
## PACKAGES
#
# 2. add o-saft.pl POD
#
# 3. add $osaft_standalone
#
# 4. include osaft.pm and OSaft/Ciphers.pm without brackets and no "package" keyword
#
# .. include text from module file enclosed in  ## PACKAGE  scope  from all modules
#
# 5. add rest of o-saft.pl
#
# 6. include cipher definitions from OSaft/Ciphers.pm
#
# 7. patch "standalone specials"
#
# 8. add separator line for POD

(
  # 1.
  $try \perl -ne 'print if (m()..m(## PACKAGES ))' $src

  # 2.
  $try $src --no-warning --no-rc --help=pod

  # 3.
  \echo ''
  \echo 'our $osaft_standalone = 1;'
  \echo ''

  \echo ""
  \echo "use Encode;"
  \echo "use IO::Socket::SSL;"
  \echo "use Net::DNS;"
  \echo "use Time::Local;"
  \echo ""

  # 4.
  # our modules without brackets

  f=osaft.pm ; [ -f $f ] || f=../$f
  \echo "# { # $f"
  #$try \perl -ne 'print if (m(## PACKAGE [{])..m(## PACKAGE })) and not m(package osaft;)' $f
  $try \perl -ne 'print if (m(## PACKAGE [{])..m(## PACKAGE }))
                    and not m(our .VERSION);
                 ' $f \
     | sed -e 's/our %ciphers /my %ciphers /'
  \echo "# } # $f"
  \echo ""

  f=OSaft/Text.pm ; [ -f $f ] || f=../$f
  \echo "{ # $f"
  $try \perl -ne 'print if (m(## PACKAGE [{])..m(## PACKAGE }))' $f
  \echo "} # $f"
  \echo ""

  f=OSaft/Ciphers.pm ; [ -f $f ] || f=../$f
  \echo "{ # $f"
  $try \perl -ne 'print if (m(## PACKAGE [{])..m(## PACKAGE }))' $f
  \echo "} # $f"
  \echo ""

  f=OSaft/Data.pm ; [ -f $f ] || f=../$f
  \echo "{ # $f"
  $try \perl -ne 'print if (m(## PACKAGE [{])..m(## PACKAGE }))' $f
  \echo "} # $f"
  \echo ""

  # ...
  ## TODO: OSaft/Doc/Data.pm
  f=OSaft/Doc/Data.pm ; [ -f $f ] || f=../$f
  \echo "{ # $f"
  $try \perl -ne 'print if (m(## PACKAGE [{])..m(## PACKAGE }))' $f
  \echo "} # $f"
  \echo ""

  ## TODO: o-saft-usr.pm  works, but not yet perfect
  f=o-saft-usr.pm ; [ -f $f ] || f=../$f
  \echo "{ # $f"
  $try \perl -ne 'print if (m(## PACKAGE [{])..m(## PACKAGE }))' $f
  #$try \cat $f
  \echo "} # $f"
  \echo ""

  ## TODO: o-saft-man  fails to include properly
  f=o-saft-man.pm ; [ -f $f ] || f=../$f
  \echo "{ # $f"
  $try \perl -ne 'print if (m(## PACKAGE [{])..m(## PACKAGE })) and not m(use osaft;)' $f \
     | \grep -v  '^use OSaft::Doc::Data'
  \echo "} # $f"
  \echo ""

  ## TODO: o-saft-dbx.pm  still with errors
  f=o-saft-dbx.pm ; [ -f $f ] || f=../$f
  \echo "{ # $f"
  $try \perl -ne 'print if (m(## PACKAGE [{])..m(## PACKAGE }))' $f
  \echo "} # $f"
  \echo ""

  f=OSaft/error_handler.pm ; [ -f $f ] || f=../$f
  \echo "{ # $f"
  #$try \perl -ne 'print if (m(## PACKAGE [{])..m(## PACKAGE }))' $f
  $try \cat $f
  \echo "} # $f"
  \echo ""

  \echo "package main;"

  f=Net/SSLinfo.pm ; [ -f $f ] || f=../$f
  \echo "{ # $f"
  $try \perl -ne 'print if (m(## PACKAGE [{])..m(## PACKAGE }))' $f
  \echo ""
  \echo 'my $_ssinfo_dum = $Net::SSLinfo::next_protos; # avoid Perl warning: "used only once: possible typo ..."'
  \echo "} # $f"
  \echo ""

  ## TODO: Net/SSLhello.pm  fails
	# Reasons: use of STR_HINT in _hint(); need: no strict 'subs'
  f=Net/SSLhello.pm
  \echo "{ # $f"
  \echo "no strict 'subs';"
  $try \perl -ne 'print if (m(## PACKAGE [{])..m(## PACKAGE }))' $f \
     | \egrep -v  '^use (osaft|OSaft::error_handler)'
  \echo "} # $f"
  \echo "package main;"
  \echo ""

  # 5.
  $try \perl -ne 'print if (not m()..m(## PACKAGES)) and not m(use osaft;)' $src \
     | \egrep -v 'require (q.o-saft-man.pm|Net::SSLhello)'

  # 6.
  f=OSaft/Ciphers.pm ; [ -f $f ] || f=../$f
  \echo "## $f DATA .. END"
  $try \perl -ne 'print if (m(## CIPHERS [{])..m(## CIPHERS }))' $f
  #$try \perl -ne 'print if (m(^__DATA__)..m(__END__))' $f
  \echo ""

  \echo "package main;"


# 7.
# to avoid duplicate definitions, "our @EXPORT" is replace by "my @EXPORT"
# TODO: "use strict;" removed, as it complains about undef %STR

) \
  | $try \perl -pe '/^=head1 (NAME|Annotation)/ && do{print "=head1 "."_"x77 ."\n\n";};' \
  | $try \sed  -e  's/#\s*OSAFT_STANDALONE\s*//' \
               -e  's/^use strict;//'    \
               -e  's/$STR/$OSaft::Text::STR/'   \
               -e  '/^use osaft/d'       \
               -e  's/^use OSaft::.*/#-# &/' \
               -e  's/^\s*our\(\s*@EXPORT\s*=\)/my \1/g'  \
               -e  '/^    sub .*{}\s*$/s/^ /#/'  \
> $dst

#               -e  's/^\(use OSaft::Text\)/# &/' \
#              -e  's/our %cipher/our %::cipher/g' 

# 8.
##TODO:

lsopt=  # tweak output if used from make
[ -z "$OSAFT_MAKE" ] && lsopt="-la"

[ "/dev/stdout" != "$dst" ] && $try \chmod 555 $dst
[ $info -eq 0 ] && exit

[ "/dev/stdout" != "$dst" ] && $try \ls $lsopt $dst

# Writing on /dev/stdout is scary on some systems (i.e Linux). If code above
# was written on /dev/stdout, the buffer may not yet flushed. Then following
# echo and cat commands,  which write on the tty's STDOUT, my overwrite what
# is already there. Some kind of race condition ...
# As the shell has no build-in posibility to flush STDOUT,  following output
# is written to /dev/stdout directly to avoid overwriting, ugly but seems to
# work ...

cat << EoDescription >> /dev/stdout
# $dst generated

	The generated stand-alone script misses following functionality:
	* Commands
		+cipherall
		+cipher-dh
	* Options
		--exit*
		--starttls
	Use of any of these commands or options will result in Perl compile
	errors like (unsorted):
		Use of uninitialized value ...
		Undefined subroutine ...
		Subroutine XXXX redefined at ...
		"our" variable XXXX redeclared at ...

	Note that  --help and --help=*  will only work if following files
	exist or are located in the same directory as  $dst :
	$osaft_doc

	"perldoc $dst"  contains all POD of all included (module) files
	in unsorted order.

	For more details for a stand-alone script, please see:
		o-saft.pl --help=INSTALL

EoDescription

exit
