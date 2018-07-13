#!/bin/sh

# TODO: funktionality of this script needs to be moved to Makefile

files="$@"

dir=perlcritic-`date +%Y%m%d`

mkdir -p $dir

echo "# $dir/ ..."

for serverity in 5 4 3; do
	echo serverity $serverity
	( 
	cd ..
	echo ""
	echo "## Anzahl Fehler ..."
	echo "# perlcritic $files -$serverity --count"
	        perlcritic $files -$serverity --count

	echo ""
	echo "## Statistik ..."
	echo "# perlcritic $files -$serverity --statistics-only"
	        perlcritic $files -$serverity --statistics-only

	echo ""
	echo "## Fehler ..."
	echo "# perlcritic $files -$serverity"
	        perlcritic $files -$serverity
	) 2>&1 | tee -a  $dir/serverity-$serverity.txt
	# 2>&1 | tee -a  $dir/serverity-$serverity.txt
done

echo "# done, results see:"
ls -l $dir/*
