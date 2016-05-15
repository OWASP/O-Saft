#!/bin/sh
#?
#? NAME
#?      $0 - einfacher Wrapper für perlcritic
#?
#? SYNOPSIS
#?      $0 [<mode>] [<policy>] <files> [perlcritic optionen]
#?
#? OPTIONEN, Argumente
#?      --h     - na sowas
#?      --n     - nix machen, nur zeigen
#?      --      - alle weiteren Argumenta an perlcritic übergeben
#?      --v     - alias für:  --verbose 10
#?      --all   - Aufruf von perlcritic für alle Quelldateien
#?      --doc   - wird direkt an perlcritic durchgereicht
#?      <mode>
#?          only     - perlcritic mit  --verbose 10 --single-policy  aufrufen
#?        --only     - Alias für  only
#?          disabled - nur die Policys prüfen, die in .perlcritic disabled sind
#?        --disabled - Alias für  disabled
#?      <policy>
#?        x::x       - jeder String, der min einmal  ::  enthält
#?
#?   Nützliche Optionen von perlcritic
#?      -5 | -4 | -3 | -2 | -1
#?                   - Severity-Level der Prüfung
#?      --doc PATTERN- Beschreibung für PATTERN ausgeben
#?      --noprofile  - .perlcriticrc ignorieren
#?      --force      - ignoriere "## no critic" Annotationen im Source-Code
#?      --nocolor    - Ausgabe nicht farblich markieren
#?      --verbose 10 - gibt zu allen Findings die Beschreibung aus
#?      --exclude PATTERN  - dieses PATTERN nicht prüfen
#?
#? BESCHREIBUNG
#?      Wrapper-Script zum vereinfachten  Aufruf von perlcritic.
#?      Werden nur Dateinamen als Argumente angegeben, dann wird perlcritic mit
#?      nur diesen aufgerufen. Bei allen anderen Argumenent wird geprüft, ob es
#?      eine Option (siehe oben) ist,  wenn nicht wird es an perlcritic überge-
#?      ben.
#?      Argumente für Policy  [<policy>]  werden automatisch erkannt, wenn min.
#?      einmal  ::  enthalten ist.
#?      Werden Policys ohne die Option  --only  angegeben,  dann werden sie mit
#?      der Option  --include  an perlcritic übergeben.
#?      Werden Policys mit -<policy>  angegeben, dann werden sie mit der Option
#?      --exclude  an perlcritic übergeben.
#?
#? BEISPIELE
#?      * normaler Aufruf (identisch zu perlcritic direkt):
#?          $0 datei
#?
#?      * nur angegebe Policy prüfen mit ausführlicher Erklärung:
#?          $0 datei  Subroutines::RequireArgUnpacking --only
#?          $0 datei  Subroutines::RequireArgUnpacking   only
#?
#?      * normaler Aufruf und zusätzlich Policy prüfen
#?          $0 datei  Subroutines::RequireArgUnpacking
#?
#?      * normaler Aufruf und Policy nicht prüfen
#?          $0 datei -Subroutines::RequireArgUnpacking
#?
#?      * nur deaktivierte Policy prüfen mit ausführlicher Erklärung:
#?          $0 datei  --disabled
#?
#?      * nur Beschreibung für PATTERN ausgeben
#?          $0 --doc ValuesAndExpressions::RequireNumberSeparators
#?
#?      * alle Dateien des Projektes mit Severity 5, 4 und 3 prüfen
#?          $0 --all
#?
#? EINSCHRÄNKUNGEN
#?      Wenn es eine Datei gibt, die genauso heisst, wie eine Policy, dann wird
#?      dieses Argument immer als Dateiname und nie als Policy-Name benutzt.
#?
#? SIEHE AUCH
#?      perlcriticrc(1)
#?      .perlcriticrc
#?
#? VERSION
#?      @(#) critic.sh 1.5 16/05/15 13:23:08
#?
#? AUTHOR
#?      06-apr-16 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

ich=${0##*/}
try=''
mode="--include";       # oder --single-policy oder leer
opts=""

our_sources="\
    osaft.pm o-saft-dbx.pm o-saft-man.pm o-saft-usr.pm \
    Net/SSLhello.pm Net/SSLinfo.pm checkAllCiphers.pl"

while [ $# -gt 0 ]; do
	arg="$1"
	shift
	case "$arg" in
	 '-h' | '--h' | '--help' | '-?')
		\sed -ne "s/\$0/$ich/g" -e '/^#?/s/#?//p' $0
		exit 0
		;;
	 '-n' | '--n') try=echo; ;;
	 '-v' | '--v') opts="--verbose 10 $opts"; ;;
	 '--only'     | 'only')                 mode="--single-policy"; ;;
	 '--disabled' | 'disabled')
		mode="--single-policy"
		pols="`perl -lne '/^\[-/ && do {$_=~s/\[-([^\]]*).*/$1/;$\=q( );print}' .perlcriticrc`"
		;;
	 '-1'  | '-2'  | '-3'  | '-4'  | '-5')  opts="$arg"; ;;
	 '--1' | '--2' | '--3' | '--4' | '--5') opts="$arg"; ;; # for lazy people
	 '--doc')                               opts="$arg"; mode=""; break; ;;
	 '--all'   | '--all-o-saft')            mode="ALLE"; files="o-saft.pl $our_sources"; break; ;;
	 '--yeast' | '--all-yeast')             mode="ALLE"; files="yeast.pl  $our_sources"; break; ;;
	 '--')  break; ;;               # alle weiteren Argumnta für perlcritic
	 *)     # es kann kommen:
		#    * Dateiname
		#    * <policy>: Subroutines::RequireArgUnpacking

		if [ -e $arg ]; then
			files="$files $arg"
			continue
		fi
		par=${arg#*::}
		if [ "$par" = "$arg" ]; then
			echo "# [$ich] unbekanntes Argument, wird an perlcritic übergeben »$par«"
			opts="$opts $arg"  # Option für perlcritic
			continue
		else
			case "$arg" in
			 -*)
				arg=${arg#*-}
				echo "# [$ich] Exclude Policy: »$arg«"
				excl="$excl --exclude $arg"
				;;
			 *)
				echo "# [$ich] Include Policy: »$arg«"
				pols="$pols $arg"
				;;
			esac
			continue
		fi

		opts="$opts $arg"       # Option für perlcritic
		;;
	esac
done

if [ "$mode" = "ALLE" ]; then
	echo "# [$ich] alle Dateien: $files"
	echo "# [$ich] Statistik"
	for serverity in -5 -4 -3; do
		echo
		echo "# [$ich] $serverity {############################################################"
		echo "# perlcritic $serverity --count           $files $opts"
		$try   \perlcritic $serverity --count           $files $opts
		echo
		echo "# perlcritic $serverity --statistics-only $files $opts"
		$try   \perlcritic $serverity --statistics-only $files $opts
		echo "# [$ich] $serverity }"
	done
	echo
	echo "# [$ich] Violations"
	for serverity in -5 -4 -3; do
		echo
		echo "# [$ich] $serverity {############################################################"
		for file in $files; do
			echo
			echo "# perlcritic $serverity $file $opts"
			$try   \perlcritic $serverity $file $opts
		done
		echo "# [$ich] $serverity }"
	done
	exit 0
fi

[ "$mode" = "--single-policy" ] && opts="--verbose 10 $opts"
if [ -n "$pols" ]; then
	for p in $pols; do
		policy="$policy $mode $p"
	done
fi

echo "# [$ich] Dateien:  $files"
echo "# [$ich] Policys:  $policy $excl"
echo "# [$ich] Optionen: $opts"
echo "# [$ich] Optionen: $@"
echo ""
echo \perlcritic $files $policy $excl $opts $@
[ -n "$try" ] && exit 0
\perlcritic $files $policy $excl $opts $@

