#!/usr/bin/gawk -f
#?
#? NAME
#?      JSON-struct.awk  - formatting o-saft.pl's output as JSON data
#?
#? SYNOPSIS
#?      o-saft.pl --tracekey --tab ... | JSON-struct.awk
#?      o-saft.pl --tracekey --tab ... | gawk -f JSON-table.awk
#?
#? DESCRIPTION
#?      Input format must be:  key\tlabel\tvalue
#?
#?      Formats all output as JSON array. The array contains following lists:
#?          *WARN, !!Hint, cipher, info, check
#?      Each list contains following elements:
#?          typ, cnt, array-of-items
#?      Each item contains:
#?          key, label, value 
#?
#? VERSION
#?      @(#) JSON-struct.awk 1.1 17/06/26 11:47:42
#?
#? AUTHOR
#?      23. June 2017 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

BEGIN {
	err[0] = ""; warn[0] = ""; hint[0] = ""; cipher[0] = 0; check[0] = ""; info[0] = "";
	FS="\t"; print "[";
	}

function trim(val)         { gsub(/^ */, "", val); gsub(/ *$/, "", val); return val; }
function line(key,val,sep) { printf("\t\t\"%s\"\t: \"%s\"%s\n", trim(key), trim(val), sep); }
function data(val) {
	#dbx##dbx# print "\t    // ", val,
	delete arr;
	split(val, arr, /\t/);
	print "\t    {";
	line("key",   arr[1], ",");
	line("label", arr[2], ",");
	line("value", arr[length(arr)]);
	print "\t    },";
}
function anf (key,cnt)     { printf("    {\n\ttyp\t: \"%s\",\n\tcnt\t: \"%s\",\n\t{\n", key, cnt); }
function end ()            { print "\t}\n    },"; }

(NF>0) { gsub(/"/,"\\\";"); }   # escape "
/^#\[/ {  sub(/^#\[/,"");  sub(/\]/,"");}   # pretty-print key:  #[key]  -->  key
/^\s*$/         { next; }       # empty lines
/^=/            { next; }       # header lines
($1~/ reading/) { next; }       # other lines

($1~/^**ERROR/)          {  err[e++]    = $0; prev_typ = "e"; next; }
($1~/^**WARN/)           { warn[w++]    = $0; prev_typ = "w"; next; }
($1~/^**HINT/)           { hint[h++]    = $0; prev_typ = "h"; next; }
#($1~/^!!Hint/)           { hint[h++]    = $0; prev_typ = "h"; next; }
($NF~/[Hh][Ii][Gg][Hh]/) { cipher[cg++] = $0; prev_typ = "c"; next; }
($NF~/[Mm][Ee][Dd][Ii]/) { cipher[cm++] = $0; prev_typ = "c"; next; }
($NF~/[Ll][Oo][Ww]/)     { cipher[cl++] = $0; prev_typ = "c"; next; }
($NF~/[Ww][Ee][Aa][Kk]/) { cipher[cw++] = $0; prev_typ = "c"; next; }
($1~/^!!Hint/)           {
	switch (prev_typ) {
	case "e": top = length(err);
	case "w": top = length(warn);
	case "c": top = length(cipher);
	case "d": top = length(check);
	case "i": top = length(info);
	}
	hint[prev_typ,top,h++]    = $0;
	next;
}
{
  if ($NF ~ /^no/ || $NF == "yes") {
	check[c++] = $0; prev_typ = "d";
  } else {
	if ($0 ~ /^cnt_/ || $0 ~ /^len_/) {
		check[c++] = $0; prev_typ = "d";
	} else {
		info[i++]  = $0; prev_typ = "i";
	}
  }
}

END {
	i = 1;
	anf("**WARN", length(warn));
	for (l in warn)   { line(i++, warn[l], ","); }
        end();

	i = 1;
	anf("!!Hint", length(hint));
	for (l in hint)   { line(i++, hint[l], ","); }
        end();

	anf("cipher", length(cipher));
	for (l in cipher) { data(cipher[l]); }
        end();

	anf("info", length(info));
	for (l in info)   { data(info[l]); }
        end();

	anf("check", length(check));
	for (l in check)  { data(check[l]); }
        end();

	print "]";
}

