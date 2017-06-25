#! /bin/sh
#?
#? NAME
#?      $0 - postprocess to colourize output of o-saft.pl
#?
#? SYNOPSIS
#?      o-saft.pl | $0 [OPTIONS]
#?
#? DESCRIPTION
#?      That's it.
#?
#? OPTIONS
#?      --h     got it
#?      --test  simple self-testing
#?      --line  colourize complete line
#?      --word  colourize special words
#?      --blind use blue instead of green
#?      --italic colourize special words and additionally print "label texts:"
#?               with italic characters
#?              "label text:" is all text left of first : including :
#?      --NUM   if a number, change assumed terminal width to NUM
#?              (used for padding text on the right);  default: terminal width
#?
#? LIMITATIONS
#?      With --line  all formatting with spaces and TABs is lost.
#?
#?      Requires additional UNIX-style programs:
#?        /bin/echo, egrep, sed, tput, wc .
#
# HACKER's INFO
#       Feel free to write your own code. You just need to add/modify the code
#       following "main" below.
#
#       How it workd, see function  testeme  below calling with  $0 --test
#       $echo is used if /bin/echo or /usr/bin/printf is needed, \echo is used
#       if shell builtin is needed.
#?
#? VERSION
#?      @(#) bunt.sh 1.7 17/06/25 20:24:07
#?
#? AUTHOR
#?      08-jan-16 Achim Hoffmann _at_ sicsec .dot. de
#?
# -----------------------------------------------------------------------------

ich=${0##*/}
_warn () {
	\echo "[$ich]: **$@" >&2
}

if [ -n "$TERM" ]; then
	case "$TERM" in
	  screen) _warn "WARNING: 'TERM=screen'; take care ..."; ;;
	esac
else
	# not a terminal, switch off terminal capabilities
	# checks are done with:    [ -z "$TERM" ]
	# probably better exit here
	true
fi

# --------------------------------------------- internal variables; defaults
try=''
dir=${0%/*}
[ "$dir" = "$0" ] && dir="." # $0 found via $PATH in .

seq=/usr/bin/seq
echo=/bin/echo
printf=0
# try to detect GNU echo
if [ -x $echo ]; then
	$echo --version | \egrep -q 'echo.*GNU'
	if [ $? -eq 0 ]; then
			echo="/bin/echo -e"
	else
		if [ -e /usr/bin/printf ]; then
			echo="/usr/bin/printf %b"
			printf=1
			_warn "WARNING: using '$echo'; take care ..."
		else
			_warn "WARNING: not GNU '$echo'; take care ..."
	    			# more escape sequenzes for GNU /bin/echo:
	    			# \a alarm    \c no more output
		fi
	fi
fi

word=1          # default: colourize words
italic=0        # default: nothing italic
_LEN=80         # default: 80 characters per line; set to termial width below
_MOD=0          # default: normal text, no highlight, bold, italic, underline, ...

	# more modes for /usr/bin/printf and GNU /bin/echo:
	# [0 normal
	# [1 bold/highlight
	# [2 dark
	# [3 normal italic
	# [4 normal underlined
	# [6 normal light gray
	# [7 reverse background
	# [8 reversed foreground (bold)
	# [9 normal strike

# colours   # escape sequence to be used in echo
#-----------+----------------------------------------
 black='0'; #  black='0;30m';	   dark_gray='1;30m'
   red='1'; #    red='0;31m';	   light_red='1;31m'
 green='2'; #  green='0;32m';	 light_green='1;32m'
 brown='3'; #  brown='0;33m';	      yellow='1;33m'
  blue='4'; #   blue='0;34m';	  light_blue='1;34m'
purple='5'; # purple='0;35m';	light_purple='1;35m'
  cyan='6'; #   cyan='0;36m';	  light_cyan='1;36m'
  gray='7'; #   gray='0;37m';	       white='1;37m'
   off='';  # used to reset colours
#-----------+----------------------------------------
# we use $_MOD later to switch to light colours

_FG=""
_BG=""  # default: do not change background
_MM=0m  # used for changing character decoration

# check terminal width
# NOTE: Unfortunatelly stty fails if we have no terminal, i.e. in cron,
#       or the intended use  in a stream (pipe).  Hence we use tput; if
#       that fails too, 80 will be hardcoded (which then may return the 
#       warning about length misatches).
arg=`\tput cols`
expr "$arg" + 0 >/dev/null ; # prints warning on STDERR
[ $? -eq 0 ] && len=$arg
if [ -n "$COLUMNS" ]; then
	# we got a hint, i.e. a bash
	[ $COLUMNS -ne $len ] && _warn "WARNING: terminal width $COLUMNS mismatch, using $len"
fi
_LEN=$len       # got it


# --------------------------------------------- functions
colour () {
	[ -z "$TERM" ] && echo $@ && return
        _bg=''
        _fg=''
	[ -n "$_BG"  ] && _bg='\033[1;4'$_BG'm'
	[ -n "$_FG"  ] && _fg='\033['$_MOD';3'$_FG'm'
	$echo "$_fg$_bg$@\033[0m\c"
	# does not print \n at end of line, must be done by caller
}

colour_reset () {
	r=$_FG; _FG=$off;   colour ""; _FG=$r
}
deco () {
	[ -z "$TERM" ] && echo $@ && return
	$echo "\033[$_MM$@\033[0m\c"
}
bold () {
	_MM=1m;  deco "$@"
}
dim () {
	_MM=2m;  deco "$@"
}
italic () {
	_MM=3m;  deco "$@"
}
underline () {
	_MM=4m;  deco "$@"
}
reversebg () {
	_MM=7m;  deco "$@"
}
reversefg () {
	_MM=8m;  deco "$@"
}
strike () {
	_MM=9m;  deco "$@"
}

# as changing text colour (forground) is the most common usage, there is one
# function for each color, and one function to just switch the background

background () {
	case "$1" in
		black)	_BG=$black ; ;;
		red)	_BG=$red   ; ;;
		green)	_BG=$green ; ;;
		brown)	_BG=$brown ; ;;
		blue)	_BG=$blue  ; ;;
		purple)	_BG=$purple; ;;
		cyan)	_BG=$cyan  ; ;;
		gray)	_BG=$gray  ; ;;
		*)	_BG=''; ;;
	esac
}

black () {
	m=$_FG; _FG=$black;    colour "$@"; _FG=$m
}
red () {
	m=$_FG; _FG=$red;      colour "$@"; _FG=$m
}
green () {
	m=$_FG; _FG=$green;    colour "$@"; _FG=$m
}
brown () {
	m=$_FG; _FG=$brown;    colour "$@"; _FG=$m
}
blue () {
	m=$_FG; _FG=$blue;     colour "$@"; _FG=$m
}
purple () {
	m=$_FG; _FG=$purple;   colour "$@"; _FG=$m
}
magenta () {
	m=$_FG; _FG=$purple;   colour "$@"; _FG=$m;  # alias for purple
}
cyan () {
	m=$_FG; _FG=$cyan;     colour "$@"; _FG=$m
}
gray () {
	m=$_FG; _FG=$gray;     colour "$@"; _FG=$m
}
white () {
	m=$_MOD; _MOD=1;       gray "$@";   _MOD=$m
}
yellow () {
	m=$_MOD; _MOD=1;       brown "$@";  _MOD=$m
}
boldred () {
	m=$_MOD; _MOD=1;       red "$@";    _MOD=$m
}
boldpurple () {
	m=$_MOD; _MOD=1;       purple "$@"; _MOD=$m
}
something () {
	m=$_MOD; _MOD=6;       purple "$@"; _MOD=$m
}
talic () {
	f=$_FG;  _FG=$gray
	m=$_MOD; _MOD=3;       colour "$@"; _MOD=$m; _FG=$f
}
reverse () {
	deco "$@"; # alias for reversebg
}

italic_label () {
	\echo "$@" | \sed -e  "s/^\(.*:\)/`italic \&`/"
}

pad_right () {
	space=""
	from=`echo "$@" | \wc -c`
	if [ $printf -eq 1 ]; then
		from=`\expr $_LEN - $from`
		_p=$@;  # printf is is really strange; squeezes spaces also
		/usr/bin/printf "%s%${from}c" "$_p"
	else
		if [ -x $seq ]; then
			for s in `$seq $from $_LEN`; do
				space="$space "
			done
		fi
		$echo "$@$space"
	fi
}

testeme () {
	reversebg "`pad_right ' line padded'`\n"
	red     " line  red\n"
	green   " line  green\n"
	brown   " line  brown\n"
	blue    " line  blue\n"
	purple  " line  purple\n"
	cyan    " line  cyan\n"
	gray    " line  gray\n"
	black   " line  black\n"
	white   " line  white\n"
	yellow  " line  yellow\n"
	underline " line  underlined\n"
	strike  " line  striked\n"
	bold    " line  bold\n"
	italic  " line  italic\n"
	something " line  something\n"
	\echo   " line with `red 'red'` word"
	\echo   " line with `red 'red'` `reversebg and` `green 'green'` `reversebg and` `underline 'underlined'` word"
	\echo   " line with `bold 'bold'` `reversebg and` `dim 'dimmed'` `reversebg and` `strike 'striked'` word"
	txt=`bold  'striked bold green'`
	txt=`strike "$txt"`
	txt=`green  "$txt"`
	\echo   " line with $txt word"
	reversebg " line reverse\n"
	italic_label "label with italic text: normal text "
	background cyan
	black   " line  black\n"
	green   " line  green\n"
	\echo   " line"
	background ''
	boldred "line bold red\n"
	colour_reset    # reset background completely
	green   "done\n"
}

# --------------------------------------------- options
while [ $# -gt 0 ]; do
	case "$1" in
	 '-h' | '--h' | '--help')
		\sed -ne "s/\$0/$ich/g" -e '/^#?/s/#?//p' $0
		exit 0
		;;
	  '--version')
		\sed -ne '/^#? VERSION/{' -e n -e 's/#?//' -e p -e '}' $0
		exit 0
		;;
	  '--line')   word=0; italic=0; ;;
	  '--word')   word=1; ;;
	  '--italic') word=1; italic=1; ;;
	  '--test') testeme; exit 0 ;;
	  '--blind')  green='4'; ;;         # use blue instead of green
	  --*)
		arg=`expr "$1" ':' '--\(.*\)'`
		expr "$arg" + 0 >/dev/null ; # prints warning on STDERR
		if [ $? -eq 0 ]; then
			[ $arg -gt $_LEN ] && \
				_warn "WARNING: given width '$arg' larger than computed size '$_LEN'"
			_LEN=$arg
		fi
		;;
	esac
	shift
done

# --------------------------------------------- main

# get o-saft.pl's markup as regex
#	o-saft.pl --help=ourstr

bgcyan () {
	background cyan
	\echo `gray  "$@"`
	colour_reset    # FIXME: does not yet work proper
}

if [ -t 0 ]; then
	_warn "ERROR: text on STDIN expected; exit"
	exit 2
fi
while read line; do
	[ -z "$line" ] &&	$echo && continue;   # speed!
	case "$line" in
		  \#\[*)	true; ;;
		  #\#yeast*CMD:*) bgcyan   "$line";     continue; ;;
		  \#*)		blue       "$line\n";   continue; ;;
		  \*\*HINT*)	purple     "$line\n";   continue; ;;
		  \*\*WARN*)	boldpurple "$line\n";   continue; ;;
		  \*\*ERROR*)	boldred    "$line\n";   continue; ;;
		  =*) reversebg "`pad_right $line`\n";  continue; ;;
		  "Use of "*perl*)  purple "$line\n";   continue; ;;
	esac
	if [ $word -eq 0 ]; then
		case "$line" in
		  *"<<"*">>"*)	cyan  "$line\n"; ;;
		  *yes*weak)	red   "$line\n"; ;;
		  *yes*WEAK)	red   "$line\n"; ;;
		  *yes*low)	red   "$line\n"; ;;
		  *yes*LOW)	red   "$line\n"; ;;
		  *yes*medium)	brown "$line\n"; ;;
		  *yes*MEDIUM)	brown "$line\n"; ;;
		  *yes*high)	green "$line\n"; ;;
		  *yes*HIGH)	green "$line\n"; ;;
		  *yes)		green "$line\n"; ;;
		  *no)		brown "$line\n"; ;;
		  *"no "*)	red   "$line\n"; ;;
		  *)		\echo "$line"; ;;
		esac
	fi

	if [ $word -eq 1 ]; then
		[ $italic -eq 1 ] && line=`italic_label "$line"`
		# first a general check to improve performance
		\echo "$line" | \egrep -q -i '(LOW|WEAK|MEDIUM|HIGH|yes)$'
		if [ $? -eq 0 ]; then
			\echo "$line" | \egrep -q 'yes$'
			[ $? -eq 0 ] && \echo "$line" | \sed -e "s/yes$/`green yes`/" && continue
			\echo "$line" | \egrep -q -i 'yes.*(WEAK|LOW|MEDIUM|HIGH)$'
				# some older sed do not support i flag, hence
				# case insensitive matching the traditional way
			[ $? -eq 0 ] && \echo "$line" | \sed \
					-e "s/\([Ll][Oo][Ww]\)$/`red \&`/"	\
					-e "s/\([Ww][Ee][Aa][Kk]\)$/`red \&`/"	\
					-e "s/\([Mm][Ee][Dd][Ii][Uu][Mm]\)$/`brown \&`/" \
					-e "s/\([Hh][Ii][Gg][Hh]\)$/`green \&`/"	\
				     && continue
			\echo  "$line"
			continue
		fi
		# anything with "no" in value is a bit special
		\echo "$line" | \egrep -q 'no$'
		[ $? -eq 0 ] && \echo "$line" | \sed -e  "s/no$/`brown no`/"  && continue
		\echo "$line" | \egrep -q 'no \('
		[ $? -eq 0 ] && \echo "$line" | \sed -e "s/\(no (.*\)/`yellow \&`/"  && continue
		\echo "$line" | \egrep -q '^#\['
		[ $? -eq 0 ] && \echo "$line" | \sed -e  "s/^\(#\[.*\]\)/`cyan \&`/"  && continue
		\echo "$line"
        fi

done

exit 0
