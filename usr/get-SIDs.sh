#!/bin/sh
#?
#? NAME
#?      $0 - generate list with filename, SID and its md5sum
#?
#? SYNOPSIS
#?      $0 [options] file [file ...]
#?      $0 [options] --make=VAR
#?      echo file file ... | $0 [options] [file ...]
#?      make e-VAR | $0 [options] [file ...]
#?
#? DESCRIPTION
#?      Generate information about version of given files. Prints one line for
#?      each file. Lines look like:
#?          3.1  24/04/24  23:23:42  md5sum    filename  path/filename
#?      Files without a SID string are reported like:
#?          0    -         -         md5sum    filename  path/filename
#?      Warnings are printed for missing files and if a file contains multiple
#?      SID strings:
#?          **WARNING: missing file filename
#?          **WARNING: duplicate SID found in filename
#?
#?      Filenames can be given on command line, piped in on STDIN or retrieved
#?      from Makefile; see  SYNOPSIS  above.
#?      All files given on command line, STDIN and Makefile are used.
#?
#? OPTIONS
#?      --help      nice option
#?      --n         don't execute, just show command
#?      --d         print some data for debugging
#?      --x         use shell's  "set -x"
#?      --make=VAR  use list of files defined in variable VAR of Makefile
#       --check     additionaly show line for file from file usr/o-saft.rel
#?      --check=REL additionaly show line for file from file REL
#?                  this options should be used with only one file argument
#         simple implementation: it's up to the user to compare printed lines
#?
#? LIMITATIONS
#?      Requires gawk.
#?
#?      Makefile  must support the pattern rule  e-%  which prints the content
#?      of the specified variable. The list will be retrieved using:
#?          make e-VAR
#?      Warning:  if make complains with errors or anything else, each word is
#?      treated as a filename.
#?
#?      --n not yet really useful.
#?
#?      Errors are expected if a filename contains non-printable characters.
#?
#? SEE ALSO
#?      Makefile
#?
# HACKER's INFO
#
#? VERSION
#?      @(#) get-SIDs.sh 3.3 25/01/11 11:45:11
#?
#? AUTHOR
#?      24. July 2024 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

#_____________________________________________________________________________
#____________________________________________________________ configuration __|
ich=${0##*/}
dir=${0%/*}
[ "$dir" = "$0" ] && dir="." # $0 found via $PATH in .
LC_COLLATE=C    # ensure that all tools behave as expected
LANG=C          # ..
dbx=
try=
osaftrel=doc/o-saft.rel     # default
rel_file=       # passed with --check=
make_var=       # for example: ALL.src
allfiles=
in_files=
out_file=/tmp/$ich.$USER.$$.log
symlinks=
missing=

#_____________________________________________________________________________
#________________________________________________________________ functions __|
_error_exit  () {
	\echo "**ERROR   [$ich]: $*; exit" >&2
	exit 2
}
_abort       () {
	\echo "**ERROR   [$ich]: canceled by user" >&2
	exit 1024
}
_dbx         () {
	[ -n "$dbx" ] && \echo "#dbx [$ich]: $*"
	return
}
_warn        () {
	\echo "**WARNING [$ich]: $*" >&2
	return
}
_get_files   () {
	# use make to get list of files; sets variable allfiles
	_var=$1
	if [ -e ./Makefile ]; then
		[ -n "$try" ] && \echo "make e-$_var" && return
		files="`\make e-$_var`"
		if [ 0 != $? -o -z "$files" ]; then
			_warn "no files returned for 'make e-$_var'" >&2
		else
			allfiles="$allfiles $files"
		fi
	else
		_warn "Makefile missing, option '--make=$_var' ignored" >&2
	fi
	return
}
_get_rel     () {
	_rel_file="$1"
	shift           # all remaining are filenames
	[ $# -lt 1 ] && return  # empty list
	if [ ! -e "$_rel_file" ]; then
		\echo "**WARNING: '$_rel_file' does not exist; --check ignored"
	else
		for f in $@ ; do
			# only grep lines with exact 6 tab-separated fields
			# last field must match given file at end,  it is a match
			# in awk because variables cannot be used like /varname/,
			# also: if the RegEx to be matched is a variable, is must
			# not be enclosed in //
			# in awk  replace / by . ; . is meta character, that's ok
			$gawk -F"\t" '
				BEGIN { f="'"$f"'"; gsub("/",".",f); r=sprintf("%s$",f);}
				($6~r){if(6==NF){print}}
			' $_rel_file
		done
	fi
	return
}

#_____________________________________________________________________________
#_____________________________________________________________________ main __|
trap _abort 2 15
# read STDIN if any
if [ ! -t 0 ]; then
	while read line; do
		[  -z "$line" ]                 && continue
		\expr "$line" : "# " >/dev/null && continue # ignore comments
	 	allfiles="$allfiles $line"
			# RegEx should be "^#" instead of "# "
			# but busybox's expr complains then with:
			#  expr: warning: '^#': using '^' as the first character
			#  of a basic regular expression is not portable; it is ignored
			# "# " seems to match at beginning of line too, but not
			# at other positions (9/2024)
	done
fi

# scan arguments
while [ $# -gt 0 ]; do
	case "$1" in
	  -h | --h | --help | '-?' | '/?')
		\sed -n -e "s/\$0/$ich/g" -e '/^#?/s/#?//p' $0
		exit 0
		;;
	  --version)   \sed -ne '/^#. *@(#)/s/#? *//p' $0 ; exit 0; ;;
	  -V | --V) \echo 3.3; exit 0; ;;
	  -n | --n) try=echo ; ;;
	  -x | --x) set -x   ; ;;
	  --d | --debug | --dbx)   dbx=echo   ; ;;
	  --check)     rel_file="$osaftrel"   ; ;;
	  --check=*)   rel_file="${1#*=}"     ; ;;
	  --make=*)    make_var="${1#*=}"     ; ;;
	  *)           allfiles="$allfiles $1"; ;;
	esac
	shift
done

# get files
[ -n "$make_var" ] && _get_files "$make_var"
if [ -z "$allfiles" ]; then
	[ -z "$try" ] && _error_exit "no files specified"
fi

# remove non-existing files from list (md5sum and gawk complain if files are missing)
for f in $allfiles; do
	if [ -L "$f" ]; then
		symlinks="$symlinks $f"
	fi
	if [ -e "$f" ]; then
		in_files="$in_files $f"
	else
		missing="$missing $f"
	fi
done

_dbx "missing=$missing"
_dbx "symlinks=$symlinks"
_dbx "in_files=$in_files"
# found files? then gawk and md5sum are required
gawk=$(  \command -v gawk)
md5sum=$(\command -v md5sum)
[ -z "$in_files" ] && _error_exit "no specified file found"
[ -z "$gawk"     ] && _error_exit "gawk missing"
[ -z "$md5sum"   ] && _error_exit "md5sum missing"

# get md5sum for each file and store in array for awk: md5["file"]="cafe";
if [ -n "$try" ]; then
	q='"'
	\echo    "md5sum $in_files |  gawk '{printf(${q}md5[\"%s\"]=\"%s\";\\\n${q},\$2,\$1)}'"
else
	md5_arr=`$md5sum $in_files | $gawk '{printf("md5[\"%s\"]=\"%s\";\n",$2,$1)}'`
fi
_dbx "md5_arr=$md5_arr"
if [ -n "$try" ]; then
	[ -n "$symlinks" ] && \echo "# symlinks: $symlinks"
	[ -n "$missing"  ] && \echo "# missing files: $missing"
	\echo "gawk '...' $in_files | sort -f -k 5" && exit 0
		# $md5_arr not printed as it may contain a huge list
fi

# print one line foreach file
# sample SID strings to be identified:
#   # SID  @(#) my.file 3.30 24/08/09 19:29:22
#   #?     @(#) my.file 1.3 24/07/27 23:01:24
#     SID="@(#) my.file 1.21 22/04/16 19:26:26"
#   our $SID_me  = "@(#) my.file 3.4 24/06/19 11:05:00"; # version
#   my  $VERSION = "@(#) my.file 1.4 20/06/05 21:20:13";
#     SID="@(#) my.file 3.1 24/01/26 00:33:37" \
#   SID="@(#) my.file 3.34 24/08/13 12:16:08"
#
# sample SID strings to be ignored:
#           @(#) $VERSION
#   my $version=~ s:^.{5}::; # remove leading @(#) as
#   @(#) 24.06.24
#   grep '@(#) ' $${_f} \
#   O-SID.pod	t/my.file /^ O-SID.pod = $(shell awk '($$1=="@(#)"){
#     @(#) my.file generated by 1.227 19/11/19 10:12:13
#     @(#) my.file 1.245 19/11/19 12:23:42',
#
(
  $gawk '
	BEGIN {
	'"$md5_arr"'
	}
	/@\(#)/ {
		# our SIDs are marked with @(#); multiple such lines may occur
		# first strip line to core SID string after @(#);  then ignore
		# lines which are not the SID of the current file; also ignore
		# duplicate SID strings
		sub(/^.*@/, "");        # remove anything left of @
		sub(/".*/,  "");        # remove anything right of "
		if ($0~/[,;]/) {next;}  # ignore lines with , or ;
		f=FILENAME;
		sub(/.*\//, "", f);     # get filename from path
		_m=sprintf("%sM%s", "%", "%");  # contribution to SCCS
		if ($2!=f && $2!=_m) {next;}
		   # ignore if filename does not match path, but allow get-SIDs.sh
		if (5==NF) {            # found valid SID
			f=FILENAME;
			if (1==md5[f]) { duplicate_entry[f]=1; next; }
			printf("%s\t%s\t%s\t%s\t%s\t%s\n",$3,$4,$5,md5[f],$2,f);
			md5[f]=1;   # mark as printed (md5sum no longer needed)
		}
	}
	END {
		# print files without SID
		for (f in md5) {
			if (1==md5[f]) {continue;}
			x=f;
			sub(/".*/,"",x);
			printf("%s\t%s\t%s\t%s\t%s\t%s\n","0","-","-",md5[f],x,f);
		}
		for (f in duplicate_entry) {
			# short message, to enforce sorting at beginning
			print "**WARNING: SID "f;
		}
	}' \
	$in_files ; # gawk

  for f in $missing; do
	\echo "**WARNING: missing file $f"
  done
) | \sort -f -k 6 | \sed -e '/^..WARNING:/s/SID/duplicate SID found in/'
    # sort field 6 which is the path and always there
# print symlinks and missing files, if any
[ -n "$symlinks" ] && \echo "**WARNING: symlinks '$symlinks'"
[ -n "$symlinks" ] && \echo "**WARNING: symlinks have SID=0 and the same md5sum as their target"

# --check=

_get_rel $rel_file $in_files

exit

# simplified version of above awk
#  gawk '/@\(#)/{sub(/^.*@/,"");;sub(/".*/,"");if($0~/[,;]/){next}f=FILENAME;sub(/.*\//,"",f);if($2!=f){next};if(5==NF){print}}' $in_files



