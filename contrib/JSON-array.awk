#!/usr/bin/gawk -f
#?
#? NAME
#?      JSON-array.awk  - formatting o-saft.pl's output as JSON array
#?
#? SYNOPSIS
#?      o-saft.pl --tracekey --tab ... | JSON-array.awk
#?      o-saft.pl --tracekey --tab ... | gawk -f JSON-array.awk
#?
#? DESCRIPTION
#?      Input format must be:  key\tlabel\tvalue
#?
#?      Formats all output as JSON array. Each array element consists of:
#?          typ, line, key, label, value
#?
#? VERSION
#?      @(#) JSON-array.awk 1.1 17/06/26 11:47:42
#?
#? AUTHOR
#?      23. June 2017 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

BEGIN { FS="\t"; e=0; w=0; h=0; c=0; d=0; i=0; print "["; }

function trim(val)         { gsub(/^ */, "", val); gsub(/ *$/, "", val); return val; }
function line(key,val,sep) { printf("\"%s\":\"%s\"%s", trim(key), trim(val), sep); }
function stat(key,val) {
	printf("  {");
	line("typ","stat", ",");
	line("key",   key, ",");
	line("value", val, "");
	print "},";
}

(NF>0) { gsub(/"/,"\\\";"); }   # escape "
/^#\[/ {  sub(/^#\[/,"");  sub(/\]/,"");}   # pretty-print key:  #[key]  -->  key
/^\s*$/         { s++; next; }  # empty lines
/^=/            { s++; next; }  # header lines
($1~/ reading/) { s++; next; }  # other lines

{ # must be first check
  if ($NF ~ /^no/ || $NF == "yes") {
	d++; typ = "check";
  } else {
	i++; typ = "info";
	if ($0 ~ /^cnt_/ || $0 ~ /^len_/) { typ = "check"; }
  }
}
($1~/^**ERROR/)          { e++; typ = "error";   $0 = sprintf("%s\t%s\t%s", e, FNR, $0); }
($1~/^**WARN/)           { w++; typ = "warning"; $0 = sprintf("%s\t%s\t%s", w, FNR, $0); }
($1~/^**HINT/)           { h++; typ = "hint";    $0 = sprintf("%s\t%s\t%s", h, FNR, $0); }
($1~/^!!Hint/)           { h++; typ = "hint";    $0 = sprintf("%s\t%s\t%s", h, FNR, $0); }
($NF~/[Hh][Ii][Gg][Hh]/) { c++; typ = "cipher"; }
($NF~/[Mm][Ee][Dd][Ii]/) { c++; typ = "cipher"; }
($NF~/[Ll][Oo][Ww]/)     { c++; typ = "cipher"; }
($NF~/[Ww][Ee][Aa][Kk]/) { c++; typ = "cipher"; }
{
	#dbx# print "  // ", $0;
	delete arr;
	split($0, arr, /\t/);
	printf("  {");
	line("typ",   typ,    ",");
	line("line",  FNR,    ",");
	line("key",   arr[1], ",");
	line("label", arr[2], ",");
	line("value", arr[length(arr)], "");
	print "},";
	next;
}

END {
	stat("error",   e);
	stat("warning", w);
	stat("cipher",  c);
	stat("check",   d);
	stat("info",    i);
	stat("skip",    s);
	print "];"; }

