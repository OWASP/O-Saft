#!/bin/sh
#?
#? NAME
#?      $0 - generate graph of subs of given perl files
#?
#? SYNOSYS
#?      $0
#?
#? DESCRIPTION
#?      Generates a graph for all subs and their call from given perl file.
#?      Some subs from standard libraries are removed to make result smaller.
#?
#?      Generates a complete graph and a simpler one where common verbose and
#?      trace subs are omitted.
#?
#? LIMITATIONS
#?      The script generates multiple files at once. The main reason is, that
#?      the output of the initial generator graph.pl needs to be modified and
#?      and then filtered before converted to other formats.
#?      Therefore use of this script may not fit into the  general concept of
#?      make which assumes one result (file) for each target.
#?
#? VERSION
#?      @(#)  1.1 23/04/17 19:54:20
#?
#? AUTHOR
#?      13-mar23 Achim Hoffmann
#?
#------------------------------------------------------------------------------

#make# ALL.SRC.perl    = $(SRC.pl) $(ALL.pm) $(CHK.pl)

dir=.
ALL_src="`(cd .. && \make e-ALL.pm)` o-saft.pl"

out_full=$dir/graph-sub-calls-full_o-saft.pl
out_simple=$dir/graph-sub-calls-simple_o-saft.pl

box2ellipse="s/shape=box,/shape=ellipse,/"  # default shape should be ellipse

if ! \command -v graph-easy 2>/dev/null ; then
	\echo "**ERROR: 'graph-easy' fehlt; Abbruch"
	exit 2
fi
dot=`\command -v dot 2>/dev/null`
[ -z "$dot" ] && \echo "**ERROR: 'dot' fehlt; .pdf und .png wird nicht erzeugt"

# Processing all files at once with graph.pl would generate a huge graph with
# only 3-4 columns. Hence each file is processed alone, and all output used
# together in one file.
#dbx# (cd .. && t/graph.pl $ALL_src ) > $out.graph.orig
(
  for src in o-saft.pl ; do
    \echo "  ( $src"
    \echo "   [$src::] {shape:rect;}"

    (cd .. && t/graph.pl $src ) \
    | \gawk '
	# input looks like:
	#       digraph mygraph {
	#       IO__Handle__read -> croak;
	#       # many more ...
	#       }
	#
	# As the node names are without quotes, some names are invalid syntax,
	# hence they are changed to:
	#       "IO__Handle__read" -> "croak";
	#
	# The default layout mode is top-down, we want left-right, so we add:
	#       rankdir=LR
	#
	# Some subs from standard libraries are removed to make result smaller.
	#
	# graph.pl replaces :: in module names by __ ; will be reverted:
	#
	# TODO: Ausgabe von graph.pl ist sortiert: immer wenn neue Name links
	#       erscheint, einen neuen subgraph beginnen. Dann sind die subs
	#       pro Datei gruppiert.
	#
	/^ *o-saft-lib/ { next; } # same as osaft.pm
	/^ *Carp__/     { next; } # remove standard lib
	/^ *Errno__/    { next; } #
	/^ *Exporter__/ { next; } #
	/^ *IO__Handle/ { next; } #
	/^ *IO__Socket/ { next; } #
	/^ *IO__import/ { next; } #
	/^ *SelectSaver/{ next; } #
	/^ *Regexp__/   { next; } #
	/^ *Socket__/   { next; } #
	/^ *Symbol__/   { next; } #
	/^ *autouse__/  { next; } #
	/^ *base__/     { next; } #
	/^ *bytes__AUTO/{ next; } #
	/^ *constant__/ { next; } #
	/^ *overloading/{ next; } #
	/->/{
		sub(/;/,"",$3);
		gsub(/__/,"::");
		gsub(/::::/,"::__");    # subs starting with __
		sub(/_pl_MAIN/,".pl::",$1);
		sub(/_pm_MAIN/,".pm::",$1);
		#s/_MAIN /:: /g;
		printf("\t[%s] -%s [%s]\n",$1,$2,$3);   # convert to GraphiViz
		next
	}
	##{print}
	' 
    echo '  )'
  done
) \
> $out_full.graph

# we have a complete graph GraphiViz syntax, now convert to other formats
# the complete graph is very complex, so we remove some low-level functions
\sed -e /_y_CMD/d -e '/_warn\]/d' -e /_trace/d -e /_v_print/d \
	$out_full.graph > $out_simple.graph

for out in $out_full $out_simple ; do
	#\dot $out.graph > $out.dot             # convert DOT
	\graph-easy  $out.graph --dot | \sed -e "$box2ellipse" > $out.dot
	\graph-easy  $out.graph --vcg                          > $out.vcg
	if [ -n "$dot" ]; then
		\dot $out.dot   -Tpdf                          > $out.pdf
		#\dot$out.dot   -Tpng                          > $out.png # huge file
		\dot $out.dot   -Tsvg                          > $out.svg
		\echo "# evince $out.pdf"
		\echo "# eog    $out.png"
	fi
	\echo "# xdot   $out.dot"
	done
exit
