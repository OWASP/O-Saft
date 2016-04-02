#!/bin/sh -x
#?
#? NAME
#?       $0 - generate o-saft_standalone.pl
#? SYNOPSIS
#?       $0
#? DESCRIPTION
#?       Generate script, which coontains all module for O-Saft.
#?
#? VERSION
#?       @(#) gen_standalone.sh 1.1 16/04/03 01:41:10
#?

dst=o-saft_standalone.pl
src=o-saft.pl
try=

o_saft="\
	osaft.pm \
	Net/SSLhello.pm \
	Net/SSLinfo.pm \
	o-saft-dbx.pm \
	o-saft-usr.pm \
	o-saft-man.pm \
"

for f in $o_saft ; do
	$try \egrep -q 'SID.*1.1' $f \
	  && \echo "**ERROR: $f wird bearbeitet; exit" \
	  && exit 2
done

$try rm -rf $dst

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


EoT

  for f in $o_saft ; do
	echo "# $f {"
	$try perl -ne 'print if m(# PACKAGE {)..m(# PACKAGE })' $f
	echo "# $f }"
	echo ""
  done

  $try cat $src

) > $dst
chmod 555 $dst

