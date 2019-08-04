#! /bin/sh
#?
#? File INSERTED_BY_MAKE
#?
#? NAME
#?      $0 - install script for O-Saft
#?
#? SYNOPSIS
#?      $0 [options] [/path/to/installation/directory]
#?
#? DESCRIPTION
#?      Some people want to have an installation script, in particular named
#?      INSTALL.sh, even O-Saft should work without a specific installation.
#?      Here we go.
#?
#?      This script does nothing except printing some messages unless called
#?      with an argument. The arguments are:
#?
#?          /absolute/path
#?                      - copy all necessary files into specified directory
#?          --install   - copy all necessary files into default directory
#?          --check     - check current installation
#?          --clean     - move files not necessary to run O-Saft into subdir
#?                        ./.files_to_be_removed
#                This is the behaviour of the old  INSTALL-devel.sh  script.
#?          --openssl   - calls  contrib/install_openssl.sh which builds and
#?                        installs  openssl  and  Net::SSLeay ; this doesn't
#?                        support other options and arguments of
#?                        contrib/install_openssl.sh
#?
#? OPTIONS
#?      --h     got it
#?      --n     do not execute, just show
#?      -x      debug using shell's "set -x"
#?      --force install RC-FILEs  .o-saft.pl  and  .o-saft.tcl  in  $HOME,
#?              overwrites existing ones
#?      --blind     use blue instead of green coloured texts; default
#?      --not-blind use green instead of blue coloured texts
#?
#? EXAMPLES
#?      $0
#?      $0 --clean
#?      $0 --check
#?      $0 --install
#?      $0 /opt/bin/
#?      $0 /opt/bin/ --force
#?
# HACKER's INFO
#       This file is generated from INSTALL-template.sh .
#       The generator (make) inserts most values for internal variables.  In
#       particular the list of source files to be installed. See the strings
#       and scopes containing  "INSERTED_BY_MAKE" .
#
#       All output is pretty printed. Yes, this adds some complexity, but it
#       is assumed that mainly humans read the output.
#
#       Environment variable inst can be set to installation directory: This
#       is usefull for development only, hence not officially documented.
#
#    echo vs /bin/echo
#       echo is a pain, depending on the platform. The shell's built-in echo
#       does not have the  -n  option, usually. /bin/echo doesn't know about
#       ANSI escape sequences, usually. \-escaped characters, like  \t , are
#       another problem, some shells support them, others do not.
#       I.g. we'd like to use traditional bourne shell, where all behaviours
#       are well defined. Unfortunately, some platforms seem to be a hostage
#       of their developers who believe that  their favorite shell has to be
#       used by all users (linking to /bin/sh to whatever, without informing
#       the user).
#       Best effort to get this script working on most platforms was:
#           * mainly use /bin/echo (aliased to echo, to keep code readable)
#           * TABs (aka \t aka 0x09) are used verbatim (see $t variable)
#           * shell's built-in echo used when ANSI escape sequences are used
#       There's no guarantee that it works flawless on everywhere, currently
#       (8/2019) it works for BSD, debian (including Mac OSX).
#       Functionallity of this script is not harmed, if the output with echo
#       fails  (prints ANSI escapes and/or \-escapes verbatim, and/or prints
#       -n verbatim, etc.).
#
#? DEPENDENCIES
#?      Following tools are required for proper functionality:
#?          awk, cat, perl, tr
#?
#? VERSION
#?      @(#)  1.32 19/08/04 19:24:24
#?
#? AUTHOR
#?      16-sep-16 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

# --------------------------------------------- internal variables; defaults
try=''
ich=${0##*/}
dir=${0%/*}
[ "$dir" = "$0" ] && dir="." # $0 found via $PATH in .
colour="34m"    # 32 green, 34 blue for colour-blind
force=0
optx=0
optn=""
mode="";        # "", check, clean, dest, openssl
alias echo=/bin/echo    # need special echo which has -n option;
	# TODO: check path for each platform
t="	"   # need a real TAB (0x09) for /bin/echo

text_miss="missing, try installing with ";
text_dev="did you run »$0 --clean«?"
text_alt="file from previous installation, try running »$0 --clean« "
text_old="ancient module found, try installing newer version, at least "

# INSERTED_BY_MAKE {
osaft_exe="OSAFT_PL_INSERTED_BY_MAKE"
osaft_gui="OSAFT_TCL_INSERTED_BY_MAKE"
contrib_dir="CONTRIB_INSERTED_BY_MAKE"
inst_directory=${inst:="INSTALLDIR_INSERTED_BY_MAKE"}

files_contrib="
	CONTRIB_INSERTED_BY_MAKE
		"

files_install="
	OSAFT_INSERTED_BY_MAKE
		"

files_install_cgi="
	OSAFT_CGI_INSERTED_BY_MAKE
		"

files_install_doc="
	OSAFT_DOC_INSERTED_BY_MAKE
		"
# INSERTED_BY_MAKE }

# HARDCODED {
# because newer Makefiles may no longer know about them

files_ancient="
	generate_ciphers_hash openssl_h-to-perl_hash o-saft-README
	INSTALL-devel.sh .perlcriticrc o-saft_bench
	contrib/.o-saft.tcl
	"

# first, dirty hack to make tests in development mode possible
[ "OSAFT_PL_INSERTED_BY_MAKE"  = "$osaft_exe"   ] && osaft_exe=o-saft.pl
[ "OSAFT_TCL_INSERTED_BY_MAKE" = "$osaft_gui"   ] && osaft_gui=o-saft.tcl
[ "CONTRIB_INSERTED_BY_MAKE"   = "$contrib_dir" ] && contrib_dir=contrib

files_not_installed="
	$contrib_dir/o-saft.cgi  $contrib_dir/o-saft.php
	$contrib_dir/Dockerfile.alpine-3.6   $contrib_dir/Dockerfile.wolfssl
	$contrib_dir/distribution_install.sh $contrib_dir/gen_standalone.sh
	$contrib_dir/install_perl_modules.pl $contrib_dir/install_openssl.sh
	$contrib_dir/INSTALL-template.sh
	"

files_develop="o-saft-docker-dev Dockerfile Makefile t/ $contrib_dir/critic.sh"

files_info="CHANGES README o-saft.tgz"
# HARDCODED }

osaft_exerc=".$osaft_exe"
osaft_guirc=".$osaft_gui"
build_openssl="$contrib_dir/install_openssl.sh"

# --------------------------------------------- internal functions
# for escape sequences, shell's built-in echo must be used
echo_yellow () {
	\echo "\033[1;33m$@\033[0m"
}
echo_green  () {
	\echo "\033[1;$colour$@\033[0m"
}
echo_red    () {
	\echo "\033[1;31m$@\033[0m"
}

# --------------------------------------------- arguments and options
while [ $# -gt 0 ]; do
	case "$1" in
	 '-h' | '--h' | '--help')
		\sed -ne "s/\$0/$ich/g" -e '/^#?/s/#?//p' $0
		exit 0
		;;
	 '-n' | '--n')  optn="--n"; try=echo ; ;;
	 '-x')          optx=1;         ;;
	  '--check')    mode=check;     ;;
	  '--clean')    mode=clean;     ;;
	  '--install')  mode=dest;      ;;  # install in hardcoded path
	  '--openssl')  mode=openssl;   ;;
	  '--force')    force=1;        ;;
	  '--blind')           colour="34m"; ;;
	  '--color-blind')     colour="34m"; ;;
	  '--colour-blind')    colour="34m"; ;;
	  '--not-blind')       colour="32m"; ;;
	  '--version')
		\sed -ne '/^#? VERSION/{' -e n -e 's/#?//' -e p -e '}' $0
		exit 0
		;;
	  '+VERSION')   echo 1.32 ; exit;     ;; # for compatibility to $osaft_exe
	  *)            inst_directory="$1"; ;; # directory, last one wins
	esac
	shift
done
clean_directory="$inst_directory/.files_to_be_removed"  # set on command line

# --------------------------------------------- main

# ------------------------- default mode --------- {
if [ -z "$mode" ]; then
	echo ""
	cat << EoT
# O-Saft does not need a specific installation.  It may be used from this
# directory right away.
#
# If you want to run O-Saft from this directory, then consider calling:

	$0 --clean .

# If you want to install O-Saft in a different directory, then please call:

	$0 /path/to/installation/directoy
	$0 /path/to/installation/directoy --force
# Optionally call:
	$0 /path/to/installation/directoy --clean

# To check if O-Saft will work, you may use:

	$0 --check .
	$0 --check /path/to/installation/directoy

# In a Docker image, this script may only be called like:

	$0 --check

EoT
	exit 0
fi; # default mode }

if [ "$mode" != "check" ]; then
	if [ -n "$osaft_vm_build" ]; then
	    echo "**ERROR: found 'osaft_vm_build=$osaft_vm_build'"
	    echo_red "**ERROR: inside docker only --check possible; exit"
	    exit 6
	fi
fi

# ------------------------- openssl mode --------- {
if [ "$mode" = "openssl" ]; then
	echo "# call $build_openssl"
	[ ! -x "$build_openssl" ] && echo_red "**ERROR: $build_openssl does not exist; exit" && exit 2
	[ 0 -lt "$optx" ] && set -x
	$build_openssl $optn $@
	status=$?
	if [ $status -ne 0 ]; then
		cat << EoT
# $build_openssl uses its default settings. To check the settings, use:
#     $0 --openssl --n
# If other configurations should be used, please use directly:
#     $build_openssl --help
#     $build_openssl --n
#     $build_openssl /path/to/install
EoT
	fi
	exit $status
fi; # openssl mode }

# ------------------------- clean mode ----------- {
if [ "$mode" = "clean" ]; then
	echo "# cleanup installation in $inst_directory"
	[ -d "$clean_directory" ] || $try \mkdir "$clean_directory/$f"
	[ -d "$clean_directory" ] || $try echo_red "**ERROR: $clean_directory does not exist; exit"
	[ -d "$clean_directory" ] || $try exit 2
	# do not move $contrib_dir/ as all examples are right there
	[ 0 -lt "$optx" ] && set -x
	cnt=0
	for f in $files_info $files_ancient $files_develop $files_install_cgi $files_install_doc $files_not_installed ; do
		#dbx echo "$clean_directory/$f"
		[ -e "$clean_directory/$f" ] && $try \rm  -f  "$clean_directory/$f"
		f="$inst_directory/$f"
		[ -e "$f" ]                  && $try \mv "$f" "$clean_directory" && cnt=`expr $cnt + 1`
	done
	echo -n "# moved $cnt files to $clean_directory "; echo_green "completed."
	exit 0
fi; # clean mode }

# ------------------------- install mode  -------- {
if [ "$mode" = "dest" ]; then
	if [ ! -d "$inst_directory" ]; then
		echo_red "**ERROR: $inst_directory does not exist; exit"
		[ "$try" = "echo" ] || exit 2
		# with --n continue, so we see what would be done
	fi

	files="$files_install $files_install_cgi $files_install_doc $files_contrib"
	[ 0 -lt "$optx" ] && set -x
	echo "# remove old files ..."
	# TODO: argh, hard-coded list of files ...
	for f in $files ; do
		f="$inst_directory/$f"
		if [ -e "$f" ]; then
			$try \rm -f "$f" || exit 3
		fi
	done

	echo "# installing ..."
	$try \mkdir -p "$inst_directory/$contrib_dir"
	$try \mkdir -p "$inst_directory/Net"
	$try \mkdir -p "$inst_directory/OSaft/Doc"
	for f in $files ; do
		$try \cp "$f" "$inst_directory/$f"  || exit 4
	done
	$try $inst_directory/$osaft_gui --rc > "$inst_directory/$osaft_guirc" \
		|| echo_red "**ERROR: generating $osaft_guirc failed"

	if [ $force -eq 1 ]; then
		echo '# installing RC-FILEs in $HOME ...'
		for f in $inst_directory/$osaft_exerc $inst_directory/$osaft_exerc ; do
			$try \cp $f "$HOME/" || echo_red "**ERROR: copying $f failed"
		done
	fi

	echo    "# consider calling: $0 --clean $inst_directory"
	echo -n "# installation in $inst_directory "; echo_green "completed."
	exit 0
fi; # install mode }

# ------------------------- check mode ----------- {
if [ "$mode" != "check" ]; then
	echo_red "**ERROR: unknow mode  $mode; exit"
	exit 5
fi

# all following is mode "check"
#[ 0 -lt "$optx" ] && set -x    # - not used here

[ -n "$optn"  ] && echo cd $inst_directory
cd $inst_directory

err=0

echo ""
echo "# check installation in $inst_directory"
echo "# (warnings are ok if 'git clone' will be used for development)"
echo "#--------------------------------------------------------------"
# err=`expr $err + 1` ; # errors not counted here
for f in $files_ancient ; do
	[ -e "$f" ] && echo -n "# found $f ...$t" && echo_yellow "$text_alt"
done
for f in $files_develop $files_info ; do
	[ -e "$f" ] && echo -n "# found $f ...$t" && echo_yellow "$text_dev"
done
echo "#--------------------------------------------------------------"

echo ""
echo "# check for installed O-Saft in $inst_directory"
echo "#----------------------+---------------------------------------"
for o in $osaft_exe $osaft_gui ; do
	cnt=0
	for p in `echo $PATH|tr ':' ' '` ; do
		f="$p/$o"
		if [ -e "$f" ]; then
		cnt=`expr $err + 1`
			v=`$p/$o +VERSION`
			perl -le 'printf"# %21s\t","'$f'"' && echo_green "$v"
		fi
	done
	[ 0 -eq $cnt ] && echo_red "$o not found"
done
echo "#----------------------+---------------------------------------"

echo ""
echo "# check for installed O-Saft resource files"
echo "#----------------------+---------------------------------------"
# currently no version check
cnt=0
for p in `echo $inst_directory $HOME $PATH|tr ':' ' '` ; do
	rc="$p/$osaft_exerc"
	if [ -e "$rc" ]; then
		cnt=`expr $err + 1`
		perl -le 'printf"# %21s\t","'$rc'"' && echo_yellow "will be used when started in $p only"
	fi
done
[ 0 -eq $cnt ] && echo_yellow "$rc not found"
rc="$HOME/$osaft_guirc"
if [ -e "$rc" ]; then
	v=`awk '/RCSID/{print $3}' $rc | tr -d '{};'`
	perl -le 'printf"# %21s\t","'$rc'"' && echo_green  "$v"
	txt="ancient"
else
	txt="missing"
fi
perl -le 'printf"# %21s\t","'$rc'"' && echo_yellow "$txt, consider generating: $osaft_gui --rc > $rc"
echo "#----------------------+---------------------------------------"

echo ""
echo "# check for installed Perl modules"
echo "#----------------------+---------------------------------------"
modules="Net::DNS Net::SSLeay IO::Socket::SSL 
	 Net::SSLinfo Net::SSLhello osaft OSaft::error_handler OSaft::Doc::Data"
for m in $modules ; do
	perl -le "printf'# %21s',$m"    # use perl instead of echo for formatting
	# NOTE: -I . used to ensure that local ./Net is found
	v=`perl -I . -M$m -le 'printf"\t%8s",$'$m'::VERSION' 2>/dev/null`
	p=`perl -I . -M$m -le 'my $idx='$m';$idx=~s#::#/#g;printf"%s",$INC{"${idx}.pm"}'`
	if [ -n "$v" ]; then
		case "$m" in
		  'IO::Socket::SSL') expect=1.90; ;; # 1.37 and newer work, somehow ...
		  'Net::SSLeay')     expect=1.49; ;; # 1.33 and newer may work
		  'Net::DNS')        expect=0.80; ;;
		esac
		case "$m" in
		  'Net::SSLinfo' | 'Net::SSLhello') c="green"; ;;
		  'OSaft::error_handler' | 'osaft') c="green"; ;;
		  'OSaft::Ciphers' )                c="green"; ;;
		  'OSaft::Doc::Data' )              c="green"; ;;
		  *) c=`perl -le "print (($expect > $v) ? 'red' : 'green')"`; ;;
		esac
		[ "$c" = "green" ] && echo_green "$v $p"
		[ "$c" = "red"   ] && echo_red   "$v $p, $text_old $expect"
		[ "$c" = "red"   ] && err=`expr $err + 1`
	else 
		text_miss="$text_miss 'cpan $m'"
		echo_red "$text_miss"
		err=`expr $err + 1`
	fi
done
echo "#----------------------+---------------------------------------"

echo ""
echo "# check for important Perl modules used by installed O-Saft"
echo "#----------------------+---------------------------------------"
modules="Net::DNS Net::SSLeay IO::Socket::SSL"
for p in `echo $PATH|tr ':' ' '` ; do
	# NOTE: output format is slightly different, 'cause it's printed what
	# $osaft_exe provides
	o="$p/$osaft_exe"
	[ -e "$o" ] || continue
	echo "# testing $o ...$t"
	for m in $modules ; do
		v=`$o --no-warn +version | awk '($1=="'$m'"){print}'`
		echo_green "$v"
	done
done
echo "#----------------------+---------------------------------------"

echo ""
echo "# check for openssl executable in PATH"
echo "#--------------+-----------------------------------------------"
echo -n "# openssl:$t"        && echo_green "`which openssl`" "(`openssl version`)"
# TODO: warning when openssl missing
# TODO: error when openssl older than 0x01000000 has no SNI
echo "#--------------+-----------------------------------------------"

echo ""
echo "# check for openssl executable used by O-Saft"
echo "#--------------+-----------------------------------------------"
# TODO: error when openssl missing
for p in `echo $PATH|tr ':' ' '` ; do
	o="$p/$osaft_exe"
	r="$p/.$osaft_exe"
	if [ -x "$o" ]; then
		(
		cd $p
		openssl=`$o --no-warn +version | awk '/external executable/{print $NF}' | tr '\012' ' '`
		echo -n "# $o:$t" && echo_green "$openssl"
		)
	fi
done
echo "#--------------+-----------------------------------------------"

echo ""
echo "# check for contributed files"
echo "# (in $inst_directory/$contrib_dir )"
echo "#--------------+-----------------------------------------------"
# TODO: $files_not_installed  should not be checked
for c in $files_contrib ; do
	c="$inst_directory/$c"
	if [ -e "$c" ]; then
		echo -n "# found  $t" &&
		echo_green  "$c"
	else
		echo -n "# missing$t" &&
		echo_yellow "$c"
		#err=`expr $err + 1`    # not counted as error
	fi
done
echo "#--------------+-----------------------------------------------"

echo ""
echo -n "# checks$t"
if [ $err -eq 0 ]; then
	echo_green "passed"
else
	echo_red   "failed , $err error(s) detected"
fi

# check mode }

exit $err

