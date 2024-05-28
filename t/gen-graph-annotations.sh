#!/bin/sh
#?
#? NAME
#?      $0 - generate graph of annotations with graph-easy for project
#?
#? SYNOPSIS
#?      $0
#?      $0 file ...
#?
#? DESCRIPTION
#?      Searches for references in all source files to other source files  or
#?      to references in themselfs.
#?
#?      Reference are:
#?          * any of the files retrieved by make
#?          * any reference using the notation:  SEE Annotation
#?
#?      Builds a graph of all found references in following files:
#?	    PREFIXgraph-annotations.*
#?      in following formats:   DOT  graph  PDF  SVG  TCL  VCG
#?
#?      To retrieved the list of source files,  make is called with a special
#?      target. The target can be specified with the  --make=T  option.  make
#?      will not be used, if files are given as arguments.
#?
#? OPTIONS
#?      --help  - WYSIWYG
#?      --v     - verbose output
#?      -x --x  - debug with shell's "set -x'
#?      --list  - show default list of source files
#?      --dir=D - generate file in directory D ;            default: .
#?      --make=T - target to retrieve list of source files; default: e-ALL.src
#?      --prefix=P  - PREFIX for generated filenames;       default:
#?
#? LIMITATIONS
#?      The script generates multiple files at once. The main reason is, that
#?      the output of the initial generator graph.pl needs to be modified and
#?      then filtered before converted to other formats.
#?      Therefore use of this script may not fit into the  general concept of
#?      make which expects one result (file) for each target.
#?
#? VERSION
#?      @(#) áÂPAÏU 3.1 24/05/29 01:09:25
#?
#? AUTHOR
#?      13-mar23 Achim Hoffmann
#?
#------------------------------------------------------------------------------

#_____________________________________________________________________________
#____________________________________________________________ configuration __|

# quick tests first
if ! \command -v graph-easy 2>&1 >/dev/null ; then
	\echo "**ERROR: 'graph-easy' missing; exit"
	exit 2
fi
dot=`\command -v dot 2>/dev/null`
[ -z "$dot" ] && \echo "**ERROR: 'dot' missing; .pdf and .png not generated"

try=
ich=${0##*/}
dir=.           # directory for generated files
out=graph-annotations
optv=
prefix=
target=e-ALL.src

ALL_src=`make $target`
SRC_ignore='
	tags
	CHANGES
	yeast.pl
	docs/o-saft.1
	contrib/o-saft-standalone.pl
	contrib/INSTALL-template.sh
'

# fully generated POD, does not make sense to use it here
POD_ignore='
	docs/o-saft.pod
'

tcl_proc='
proc graphs_scroll  w {
   set pa [set pa0 [winfo parent $w]]
   if {$pa eq "."} {set pa ""}
   grid $w [scrollbar $pa.y -command "$w yview"] -sticky news
   $w configure -xscrollcommand "$pa.x set" -yscrollcommand "$pa.y set"
   grid $pa.y -sticky ns
   grid [scrollbar $pa.x -ori hori -command "$w xview"] -sticky ew
   grid columnconfigure $pa0 0 -weight 1
   grid rowconfigure    $pa0 0 -weight 1
}; # graphs_scroll

set c [canvas .c]
graphs_create .c
.c config -scrollregion [.c bbox all]
graphs_scroll .c
wm geometry   .  1024x1024
'

#_____________________________________________________________________________
#________________________________________________________________ functions __|

_vprint() {
	[ -n "$optv" ] && \echo "# $@ ..." >&2
	return 0
} # _vprint

# [ o-saft.pl ] { origin: Perl:BEGIN; offset: 4,0; }

see_graph_easy() {
	# generate graph for Annotation with "SEE"
	_out="$1"
	_vprint "  see_graph_easy $_out. ..."
	_cnt_src=`\echo  "$ALL_sort"            | \wc -w`
	_cnt_see=`\egrep '# SEE  *' $ALL_sort   | \wc -l`
	_cnt_ann=`\egrep '^=head2'  $ALL_nopod  | \wc -l`
	(
	  \cat <<EoT
( Statistics
  [$_cnt_src source files]
	== $_cnt_see references ==>
	[$_cnt_ann annnotations] {shape:ellipse;}
) { color:black; background:yellow; }
( Legend
  [Source file with reference to annotation] 
	== line not black ==> {color:#ff20ff;}
	[SEE Annotation] {shape:ellipse;}

  [=head2 Annotation]    {shape:ellipse;}
	== black line     ==>
	[Source file with annotation]
  [ NOTE:
	\nall definitions of "=head2 Annotaions" (box where black arrows start)
	\nmust be shape:ellipse, anything else is a bug in graph-easy
   	\n====================================================
  ]
) { color:black; background:yellow; }
EoT
	#\--- buggy graph-easy does not handle group attributes

#TODO:  neet to search and santise L<anotation>
	  for _src in $ALL_sort ; do
		#_vprint " SEE in $_src ..."
		# searching lines like:
		#    some text # SEE Annotation header text (text to be removed)
		# and converts to:
		#    [filename] --> [header text]
		# gold is #ffd700 but that's barely visible hence we use orange
		\perl -lne '
			if (not m/(^|\s+)# SEE /){next;}
			s/.*# SEE //;
			s/\([^)]*\)$//;
			$c = "";
			if ($ARGV =~ m#^Makefile*#) { $c = "{color:#0000ff;}"; } # blue
			if ($ARGV =~ m#^t/*#)       { $c = "{color:#0000ff;}"; }
			if ($ARGV =~ m#^docs/*#)    { $c = "{color:#00ff00;}"; } # green
			if ($ARGV =~ m#^Net*#)      { $c = "{color:#ff9900;}"; } # gold
			if ($ARGV =~ m#^o-saft*#)   { $c = "{color:#ff9900;}"; } # gold
			if ($ARGV =~ m#^OSaft/*#)   { $c = "{color:#ff9900;}"; }
			if ($ARGV =~ m#^contrib/*#) { $c = "{color:#dda0dd;}"; } # plum
			printf("[%s] --> %s [%s] {shape:ellipse;}\n",$ARGV,$c,$_);
			' $_src
	  done

	  for _src in $ALL_nopod ; do
		#_vprint " =head2 in $_src ..."
		[ yeast.pl  = $_src ]   && continue   # ignore development file
		# searching lines like:
		#    =head2 Annotation header text
		# and converts to: 
		#    [header text] -> [filename]
		\perl -lne '
			if (m/L</){next;} # avoid in graph-easy: Cannot find autosplit node for L<.... on edge 1019 at /usr/bin/graph-easy line 90.
			if (m/^=head2 /){
			s/=head2 //;
				s/([\[\]|])/\\$1/g;  # graph-easy is picky
				#printf("[%s] --> %s [%s]\n",$ARGV,$c,$_);
				printf("[%s] --> %s [%s]\n",$_,$c,$ARGV);
			}' $_src
	  done
	) | \graph-easy         --txt --output=$_out.graph
        \echo "# generated by gen-graph-annotations.sh 3.1" >>$_out.graph
	\graph-easy $_out.graph --dot --output=$_out.dot
	\graph-easy $_out.graph --vcg --output=$_out.vcg
	\graph-easy $_out.dot   --pdf --output=$_out.pdf
	_vprint "evince $out.pdf"
	_vprint "xdot   $out.dot"
	[ -z "$dot" ] && return 0
	#\dot        $_out.dot   -Tpdf        > $_out.pdf # generated above
	#\dot        $_out.dot   -Tpng        > $_out.png # huge file
	\dot        $_out.dot   -Tsvg        > $_out.svg
	_vprint "eog    $out.svg"
	(
	  \cat <<EoT    # using cat instead of echo to avoid dragons with !
#!/usr/bin/wish
# generated by gen-graph-annotations.sh 3.1
proc graphs_create c {

EoT
	  \dot      $_out.dot   -Ttk \
	  | \perl -lne '
		s/-width 1 /-width 2 /g; # graphs are to thin
		print;
		'
	  \echo ""
	  \echo "}; # graphs_create"
	  \echo ""
	  \echo "$tcl_proc"
	) > $_out.tcl
	\chmod +x $_out.tcl
	_vprint "wish   $out.tcl #or#  $out.tcl"
	return 0
} # see_graph_easy

#_____________________________________________________________________________
#_____________________________________________________________________ main __|

args=
while [ $# -gt 0 ]; do
	case "$1" in
	 -h | --h | --help | '-?' | '/?')
		\sed -ne "s/\$0/$ich/g" -e '/^#?/s/#?//p' $0
		exit 0
		;;
	 -n | --n) try=echo      ; ;;
	 -v | --v) optv=--v      ; ;;
	 -x | --x) set -x        ; ;;
	 --list)     \echo $ALL_src; exit 0 ;;
	 --dir=*)    dir="`   expr "$1" ':' '--dir=\(.*\)'`"    ; ;;
	 --make=*)   target="`expr "$1" ':' '--make=\(.*\)'`"   ; ;;
	 --prefix=*) prefix="`expr "$1" ':' '--prefix=\(.*\)'`" ; ;;
	*)      args="${args} $1"; ;;
	esac
	shift
done

if [ -n "$args" ]; then
	ALL_src=$args
	ALL_sort=$args
	ALL_nopod=$args
else
	ALL_src=`\make $target`
	ALL_sort=`\echo $ALL_src $SRC_ignore   | \tr " " "\012" | \sort -d | \uniq -u`
	ALL_nopod=`\echo $ALL_src $POD_ignore  | \tr " " "\012" | \sort -d | \uniq -u`
fi
#dbx# \echo args=$args
#dbx# \echo ALL=$ALL_sort

out=${prefix}graph-annotations

_vprint "------------------------------------ search references to annotation #{"
see_graph_easy $dir/$out 
[ -n "$optv" ] && \ls -l $dir/$out.*
_vprint "---------------------------------------------------------------------#}"
exit

#
