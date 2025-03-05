#!/bin/sh
#?
#? NAME
#?      o-saft_bench.sh  - simple time and memory test program for o-saft.pl
#? SYNOPSYS
#?      o-saft_bench.sh [target host]
#? DESCRIPTION
#?      Runs  o-saft.pl with most common commands and measures execution and
#?      memory usage using system's  /usr/bin/time  command.
#?      Results are written to STDOUT, the calling program is responsible to
#? RESULTS                                                                     
#?      Expected results are like:                                             
#?
#?#--------------------------------------+-----+-----+--------+----+---+-------+
#?#                                      |    time            |    |  memory   |
#?#         command                      | user system   real | CPU| av.   max |
#?#--------------------------------------+-----+-----+--------+----+---+-------+
#?o-saft.pl --exit=BEGIN0                | 0.00  0.00  0:00.00  80%  0k   5272k  
#?o-saft.pl +VERSION           --norc    | 0.00  0.00  0:00.00  80%  0k   5440k  
#?o-saft.pl +version                     | 0.14  0.01  0:00.17  92%  0k  29648k 
#?...                                                                           
#?o-saft.pl +cipher                $host | 4.60  0.23  0:05.35  90%  0k  45468k 
#?o-saft.pl +cipherall             $host | 0.96  0.05  0:01.74  58%  0k  26696k 
#?o-saft.pl +info                  $host | 0.18  0.04  0:02.38   9%  0k  25820k 
#?...                                                                           
#?#--------------------------------------+-----+-----+--------+----+---+-------+
#?
#?      Brief explanation (based on a 3 GHz CPU with 16 GB RAM):
#?          * no ERRORs or WARNINGs should be printed
#?          *   user time: 0.1x is good for informational commands
#?          * system time: 0.01 is good for informational commands
#?          * system time: 0.2x is good for info and check commands
#?          *   user time: 4.xx is good for info and check commands
#?          *   real time: 0:05.xx is good for +cipher command
#?          *   real time: 0:01.xx is good for +cipherall command
#?          *   real time: 0:07.xx is good for most check commands
#?          * ca.  memory:  6000 kB is good for +VERSION command
#?          * max. memory: 35000 kB is good for info command
#?          * max. memory: 45000 kB is good for cipher and check commands
#?
#? VERSION
#?      @(#) o-saft_bench.sh 1.23 25/03/05 22:40:43
#? AUTHOR
#?      07-Jul-14 Achim Hoffmann
# -----------------------------------------------------------------------------

  SID="@(#) o-saft_bench.sh 1.23 25/03/05 22:40:43"


  ich=${0##*/}
osaft=../o-saft.pl
 host=localhost
 time=/usr/bin/time
  out=./${ich}.times    # not used anymore, must be done by caller

 LANG=C
export LANG

while [ $# -gt 0 ]; do
	case "$1" in
	 '-h' | '--h' | '--help')
		\sed -ne "s/\$0/$ich/g" -e '/^#?/s/#?//p' $0; exit 0; ;;
	'+VERSION')	echo "1.23"; exit 0; ;;
	*)	host="$1"; ;;
	esac
	shift
done

[ -x $osaft ] || osaft=o-saft.pl
$osaft +quit > /dev/null
if [ $? != 0 ]; then
	echo "**ERROR: $osaft failed; exit" && exit 2
fi

echo
echo -n "# " && date
echo    "# $SID"
echo -n "# o-saft.pl +VERSION: " && $osaft +VERSION --norc
echo -n "# System (uname -a):  " && uname -s -v -r -m -o
echo -n "# Perl   (perl -v):   " && perl -v|grep This
echo    "#"
echo    "# testing with target: \$host = $host"

# dummy to load modules and alocate memory, otherwise first test results are misleading
$osaft +check localhost --trace --user >/dev/null 2>&1

   t="%U  %S  %E  %P  %Kk  %Mk" # format for time, improved by following awk
line="#--------------------------------------+-----+-----+--------+----+---+-------+"
echo $line
echo "#                                      #    time            |    |  memory   |"
echo "#         command                      # user system   real | CPU| av.   max |"
echo $line

while read -r cmd ; do
	[ -z "$cmd" ] && continue  # skip final emtpy line
	txt=`echo "$cmd" | \sed -e "s/ $host/ "'$host/' -e 's/\\\/|/'`
		# we want a well formatted table, hence the real hostname is
		# replaced by the fixed string $host
	cmd=`echo "$cmd" | \sed -e 's/ *#$//'`
	#dbx# echo    "o-saft.pl $cmd "
	#dbx# echo "$txt #"
	echo -n "o-saft.pl $txt" && \
	$time --quiet -f "$t" $osaft $cmd 2>&1 >/dev/null \
	| awk '{printf"%5s %5s %8s %4s %3s %7s\n",$1,$2,$3,$4,$5,$6}'
		# awk is just for pretty printing
		# NOTE: --exit=BEGIN0 is some kind of minimal (perl) resources
		# NOTE: time writes on tty, hence redirect to STDOUT, the final
		#       >/dev/null at end handles output from $osaft, crazy ...
		# following line produces strange results when used with time:
	# --exit=BEGIN0                #
done << EoT
	+VERSION           --norc    #
	+version                     #
	+version --v --usr           #
	+version           --norc    #
	+version --v       --norc    #
	+libversion                  #
	+libversion        --norc    #
	+ciphers                     #
	+ciphers -V                  #
	+list                        #
	--v +help                    #
        --help=gen-wiki              #
        --help=gen-wiki --no-header  #
	+cipher                $host #
	+cipherall             $host #
	+info                  $host #
	+info  --noopenssl     $host #
	+quick                 $host #
	+quick --noopenssl     $host #
	+check                 $host #
	+check --noopenssl     $host #
	+sizes                 $host #
	+sizes --trace-cmd --trace-time $host #
	+quit  --trace-cmd --trace-time       #
EoT
# tricky here document:
# final  #  is used to format the text and is also the separator between
# command and time values.

echo $line
exit

#=============================================================================#
#== output should look like                                                 ==#
## following old output up to 6/2015, modern one see description above

# Mi 23. Jul 23:42:11 MEST 2014
# o-saft.pl +VERSION: 14.07.25
# System (uname -a):  Linux circe 2.6.38-16-generic #66-heureca x86_64 x86_64 x86_64 GNU/Linux
# Perl   (perl -v):   This is perl, v5.10.1 (*) built for x86_64-linux-gnu-thread-multi
#
#                                      |       time          |    |  memory   |
#         command                      | user system    real | CPU| av.  max  |
#--------------------------------------+------+-----+--------+----+---+-------+
o-saft.pl +VERSION           --norc    | 2.63  0.86  0:03.50  99%  0k  6239184k
o-saft.pl +version                     | 2.49  1.20  0:03.72  99%  0k  6248544k
o-saft.pl +version --v --usr           | 2.79  0.94  0:03.78  98%  0k  6250304k
o-saft.pl +version           --norc    | 2.60  1.10  0:03.74  98%  0k  6248416k
o-saft.pl +version --v       --norc    | 2.64  1.07  0:03.74  99%  0k  6249344k
o-saft.pl +libversion                  | 2.56  1.13  0:03.72  99%  0k  6243664k
o-saft.pl +libversion        --norc    | 2.76  0.94  0:03.74  98%  0k  6243520k
o-saft.pl +ciphers                     | 2.78  0.73  0:03.53  99%  0k  6243680k
o-saft.pl +ciphers -V                  | 2.83  0.89  0:03.74  99%  0k  6243648k
o-saft.pl +list                        | 2.70  0.82  0:03.54  99%  0k  6243680k
o-saft.pl --v +help                    | 2.62  0.90  0:03.53  99%  0k  6240464k
o-saft.pl +gen-wiki                    | 2.72  0.81  0:03.74  94%  0k  6245056k
o-saft.pl +gen-wiki    --usr           | 2.52  0.97  0:03.51  99%  0k  6240336k
o-saft.pl +cipher            localhost | 3.10  2.13  0:06.01  86%  0k  6258048k
o-saft.pl +cipherall         localhost | 2.97  0.88  0:04.23  90%  0k  6251248k
o-saft.pl +info              localhost | 2.77  1.95  0:04.96  94%  0k  6253888k
o-saft.pl +info  --noopenssl localhost | 2.77  0.78  0:03.64  97%  0k  6253136k
o-saft.pl +quick             localhost | 3.06  2.15  0:06.02  86%  0k  6259936k
o-saft.pl +quick --noopenssl localhost | 3.17  0.90  0:04.74  85%  0k  6259168k
o-saft.pl +check             localhost | 3.22  2.06  0:06.09  86%  0k  6260160k
o-saft.pl +check --noopenssl localhost | 3.25  1.02  0:04.97  85%  0k  6259616k
o-saft.pl +sizes                 $host | 0.14  0.00  0:02.32  6%   0k  22864k
o-saft.pl +sizes --trace-cmd --trace-time $host | 0.13  0.02  0:02.32  6%   0k  23224k
o-saft.pl +quit  --trace-cmd --trace-time       | 0.11  0.01  0:00.13  97%  0k  21628k
#--------------------------------------+------+-----+--------+----+---+-------+

