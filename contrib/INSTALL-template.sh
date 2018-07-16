#! /bin/sh
#?
#? File INSERTED_BY_MAKE
#?
#? NAME
#?      $0 - install script for O-Saft
#?
#? SYNOPSIS
#?      $0 [options] [installation directory]
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
#?                        ./release_information_only
#                This is the behaviour of the old  INSTALL-devel.sh  script.
#?          --openssl   - use  contrib/build_openssl.sh  to install  openssl
#?                        and  Net::SSLeay
#?
#? OPTIONS
#?      --h     got it
#?      --n     do not execute, just show
#?      --blind use blue instead of green coloured texts
#?      --force install .o-saft.pl  and  .o-saft.tcl  in  $HOME,  overwrites
#?              existing ones
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
#       The generator (make) inserts some values for internal variables.  In
#       particular the list of source files to be installed. See the strings
#       INSERTED_BY_MAKE .
# TODO: --check does not work if installed in other dir than default one
#
#       Environment variable inst can be set to installation directory: This
#       is usefull for development only, hence not officially documented.
#
#? DEPENDENCIES
#?      Following tools are required for proper functionality:
#?          awk, cat, perl, tr
#? VERSION
#?      @(#) INSTALL-template.sh 1.12 18/07/16 11:53:45
#?
#? AUTHOR
#?      16-sep-16 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

# --------------------------------------------- internal variables; defaults
try=''
ich=${0##*/}
bas=${ich%%.*}
dir=${0%/*}
[ "$dir" = "$0" ] && dir="." # $0 found via $PATH in .
colour="32m"    # 32 green, 34 blue for colour-blind
clean=./release_information_only
force=0
optn=""
mode="";        # "", check, clean, dest
inst=${inst:="INSTALLDIR_INSERTED_BY_MAKE"}

text_miss="missing, try installing with ";	# 'cpan $m'"
text_dev="did you run »$0 --clean«?"
text_alt="file from previous installation, try running »$0 --clean« "
text_old="ancient module found, try installing newer version, at least "


files_contrib="
	CONTRIB_INSERTED_BY_MAKE
		"

files_install="
	OSAFT_INSERTED_BY_MAKE
		"

files_not_installed="
		o-saft.cgi contrb/o-saft.php contrib/install_perl_modules.pl
		"

files_develop=".perlcriticrc o-saft_bench o-saft-docker-dev Dockerfile"

files_ancient="generate_ciphers_hash openssl_h-to-perl_hash o-saft-README INSTALL-devel.sh"

files_info="CHANGES README o-saft.tgz"

# --------------------------------------------- internal functions
echo_yellow () {
	echo "\033[1;33m$@\033[0m"
}
echo_green  () {
	echo "\033[1;$colour$@\033[0m"
}
echo_red    () {
	echo "\033[1;31m$@\033[0m"
}

# --------------------------------------------- arguments and options
while [ $# -gt 0 ]; do
	case "$1" in
	 '-h' | '--h' | '--help')
		\sed -ne "s/\$0/$ich/g" -e '/^#?/s/#?//p' $0
		exit 0
		;;
	 '-n' | '--n')  optn="--n"; try=echo; ;;
	  '--check')    mode=check; ;;
	  '--clean')    mode=clean; ;;
	  '--install')  mode=dest;  ;; # install in hardcoded path
	  '--openssl')  mode=openssl; ;;
	  '--force')    force=1;    ;;
	  '--blind')           colour="34m"; ;;
	  '--color-blind')     colour="34m"; ;;
	  '--colour-blind')    colour="34m"; ;;
	  '--version')
		\sed -ne '/^#? VERSION/{' -e n -e 's/#?//' -e p -e '}' $0
		exit 0
		;;
	  '+VERSION')   echo 1.12 ; exit; ;; # for compatibility to o-saft.pl
	  *)            mode=dest; inst="$1";  ;;  # last one wins
	esac
	shift
done

# --------------------------------------------- main

# ------------------------- default mode --------- {
if [ -z "$mode" ]; then
	echo ""
	cat << EoT
# O-Saft does not need a specific installation.  It may be used from this
# directory right away.
#
# If you want to run O-Saft from this directory, then consider calling:

	$0 --clean

# If you want to install O-Saft in a different directory, then please call:

	$0 /path/to/installation/directoy
	$0 /path/to/installation/directoy --force

# To check if O-Saft will work, you may use:

	$0 --check

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
	build=contrib/build_openssl.sh
	[ ! -x "$build" ] && echo_red "**ERROR: $build does not exist; exit" && exit 2
	$build $optn
	status=$?
	if [ $status -ne 0 ]; then
		cat << EoT
# $build uses its default settings. To check the settings, use:
#     $0 --openssl --n
# If other configurations should be used, please use directly:
#     $build --help
#     $build --n
#     $build /path/to/install
EoT
	fi
	exit $status
fi; # openssl mode }

# ------------------------- clean mode ----------- {
if [ "$mode" = "clean" ]; then
	# do not move contrib/ as all examples expect contrib/ right here    
	for f in $files_info $files_ancient $files_develop ; do
		[ -e "$clean/$f" ] && $try \rm -f "$clean/$f"
		$try \mv "$f" "$clean"
	done
	exit 0
fi; # clean mode }

# ------------------------- install mode  -------- {
if [ "$mode" = "dest" ]; then
	if [ ! -d "$inst" ]; then
		echo_red "**ERROR: $inst does not exist; exit"
		[ "$try" = "echo" ] || exit 2
	fi

	echo "# remove old files ..."
	# TODO: argh, hard-coded list of files ...
	for f in $files_install ; do
		f="$inst/$f"
		if [ -e "$f" ]; then
			$try \rm -f "$f" || exit 3
		fi
	done

	echo "# installing ..."
	$try \mkdir -p "$inst/Net"
	$try \mkdir -p "$inst/OSaft/Doc"
	for f in $files_install ; do
		$try \cp "$f" "$inst/$f"  || exit 4
	done

	if [ $force -eq 1 ]; then
		$try \cp .o-saft.pl  "$inst/"         || echo_red ".o-saft.pl  failed"
		$try \cp contrib/.o-saft.tcl "$inst/" || echo_red ".o-saft.tcl failed"
	fi

	echo -n "# installation in $inst "; echo_green "completed."
	exit 0
fi; # install mode }

# ------------------------- check mode ----------- {
if [ "$mode" != "check" ]; then
	echo_red "**ERROR: unknow mode  $mode; exit"
	exit 5
fi

# all following is check mode

err=0

echo ""
echo "# check installation"
echo "# (warnings are ok if 'git clone' will be used for development)"
echo "#--------------------------------------------------------------"
# err=`expr $err + 1` ; # errors not counted here
files="openssl_h-to-perl_hash generate_ciphers_hash o-saft-README"
for f in $files ; do
	[ -e "$f" ] && echo -n "# found $f ...\t" && echo_yellow "$text_alt"
done
files="$files_develop $files_info "
for f in $files ; do
	[ -e "$f" ] && echo -n "# found $f ...\t" && echo_yellow "$text_dev"
done
echo "#--------------------------------------------------------------"

echo ""
echo "# check for installed O-Saft"
echo "#--------------------------------------------------------------"
for o in o-saft.pl o-saft.tcl ; do
	for p in `echo $PATH|tr ':' ' '` ; do
		d="$p/$o"
		if [ -e "$d" ]; then
			v=`$p/$o +VERSION`
			echo -n "# version $v:\t" && echo_green "$d"
		fi
	done
done
echo "#--------------------------------------------------------------"

echo ""
echo "# check for installed O-Saft resource files"
echo "#--------------------------------------------------------------"
# currently no version check
rc="$HOME/.o-saft.tcl"
if [ -e "$rc" ]; then
	v=`awk '/RCSID/{print $3}' $rc | tr -d '{};'`
	echo -n "# found $rc\t"   && echo_green "$v"
	echo -n "# exist $rc\t"   && echo_yellow "consider updating from contrib/.o-saft.tcl"
else
	echo -n "# miss. $rc\t"   && echo_yellow "consider copying contrib/.o-saft.tcl into your HOME directory: $HOME"
fi
for p in `echo $HOME $PATH|tr ':' ' '` ; do
	rc="$p/.o-saft.pl"
	if [ -e "$rc" ]; then
		echo -n "# $rc\t" && echo_yellow "will be used when started in $p only"
	fi
done
echo "#--------------------------------------------------------------"

echo ""
echo "# check for installed perl modules"
echo "#--------------------------------------------------------------"
modules="Net::DNS Net::SSLeay IO::Socket::SSL Net::SSLinfo Net::SSLhello osaft OSaft::error_handler"
for m in $modules ; do
	echo -n "# testing for $m ...\t"
	v=`perl -M$m -le 'printf"\t%s",$'$m'::VERSION' 2>/dev/null`
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
		  *) c=`perl -le "print (($expect > $v) ? 'red' : 'green')"`; ;;
		esac
		[ "$c" = "green" ] && echo_green "$v"
		[ "$c" = "red"   ] && echo_red   "$v , $text_old $expect"
		[ "$c" = "red"   ] && err=`expr $err + 1`
		[ "$c" = "red"   ] && echo E $err
	else 
		text_miss="$text_miss 'cpan $m'"
		echo_red "$text_miss"
		err=`expr $err + 1`
		echo e $err
	fi
done
echo "#--------------------------------------------------------------"

echo ""
echo "# check for important perl modules used by O-Saft"
echo "#--------------------------------------------------------------"
modules="Net::DNS Net::SSLeay IO::Socket::SSL"
for p in `echo $PATH|tr ':' ' '` ; do
	o="$p/o-saft.pl"
	[ -e "$o" ] || continue
	echo "# testing $o ...\t"
	for m in $modules ; do
		v=`$o --no-warn +version | awk '($1=="'$m'"){print}'`
		echo_green "$v"
	done
done
echo "#--------------------------------------------------------------"

echo ""
echo "# check openssl executable in PATH"
echo "#--------------------------------------------------------------"
echo -n "# openssl:\t\t"        && echo_green "`which openssl`"
echo -n "# openssl version:\t"  && echo_green "`openssl version`"
# TODO: openssl older than 0x01000000 has no SNI
echo "#--------------------------------------------------------------"

echo ""
echo "# check for openssl executable used by O-Saft"
echo "#--------------------------------------------------------------"
for p in `echo $PATH|tr ':' ' '` ; do
	o="$p/yeast.pl"
	r="$p/.o-saft.pl"
	if [ -x "$o" ]; then
		(
		cd $p
		openssl=`$o --no-warn +version | awk '/external executable/{print $NF}' | tr '\012' ' '`
		echo -n "# $o:\t" && echo_green "$openssl"
		)
	fi
done
echo "#--------------------------------------------------------------"

echo ""
echo "# check for contributed files"
echo "# (in $inst )"
echo "#--------------------------------------------------------------"
for c in $files_contrib ; do
	c="$inst/$c"
	if [ -e "$c" ]; then
		echo -n "# found\t"     && echo_green "$c"
	else
		echo -n "# not found\t" && echo_red   "$c"
		err=`expr $err + 1`
	fi
done
echo "#--------------------------------------------------------------"

echo ""
echo -n "# checks\t"
if [ $err -eq 0 ]; then
	echo_green "passed"
else
	echo_red   "failed , $err error(s) detected"
fi

# check mode }

exit $err

