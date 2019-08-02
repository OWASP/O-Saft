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
#?      --force install .o-saft.pl  and  .o-saft.tcl  in  $HOME,  overwrites
#?              existing ones
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
#?      @(#)  1.24 19/08/02 08:37:22
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
colour="34m"    # 32 green, 34 blue for colour-blind
clean=./.files_to_be_removed
force=0
optx=0
optn=""
mode="";        # "", check, clean, dest
inst=${inst:="INSTALLDIR_INSERTED_BY_MAKE"}

text_miss="missing, try installing with ";	# 'cpan $m'"
text_dev="did you run »$0 --clean«?"
text_alt="file from previous installation, try running »$0 --clean« "
text_old="ancient module found, try installing newer version, at least "

osaft_exe="o-saft.pl"
osaft_gui="o-saft.tcl"
# corresponding RC-files do not need their own variable; simply prefix with .

inst_openssl="contrib/install_openssl.sh"

# INSERTED_BY_MAKE {
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

# following lists are hardcoded here, because newer Makefiles may no longer
# know about them
files_not_installed="
		contrib/o-saft.cgi pcontrib/o-saft.php
		contrib/Dockerfile.alpine-3.6   contrib/Dockerfile.wolfssl
		contrib/distribution_install.sh contrib/gen_standalone.sh
		contrib/install_perl_modules.pl contrib/install_openssl.sh
		contrib/INSTALL-template.sh
		"

files_ancient="generate_ciphers_hash openssl_h-to-perl_hash o-saft-README
		INSTALL-devel.sh .perlcriticrc o-saft_bench
		"

files_develop="o-saft-docker-dev Dockerfile Makefile t/ contrib/critic.sh"

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
	 '-x')          optx=1;     ;;
	  '--check')    mode=check; ;;
	  '--clean')    mode=clean; ;;
	  '--install')  mode=dest;  ;; # install in hardcoded path
	  '--openssl')  mode=openssl; ;;
	  '--force')    force=1;    ;;
	  '--blind')           colour="34m"; ;;
	  '--color-blind')     colour="34m"; ;;
	  '--colour-blind')    colour="34m"; ;;
	  '--not-blind')       colour="32m"; ;;
	  '--version')
		\sed -ne '/^#? VERSION/{' -e n -e 's/#?//' -e p -e '}' $0
		exit 0
		;;
	  '+VERSION')   echo 1.24 ; exit; ;; # for compatibility to $osaft_exe
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
	[ ! -x "$inst_openssl" ] && echo_red "**ERROR: $inst_openssl does not exist; exit" && exit 2
	[ 0 -lt "$optx" ] && set -x
	$inst_openssl $optn $@
	status=$?
	if [ $status -ne 0 ]; then
		cat << EoT
# $inst_openssl uses its default settings. To check the settings, use:
#     $0 --openssl --n
# If other configurations should be used, please use directly:
#     $inst_openssl --help
#     $inst_openssl --n
#     $inst_openssl /path/to/install
EoT
	fi
	exit $status
fi; # openssl mode }

# ------------------------- clean mode ----------- {
if [ "$mode" = "clean" ]; then
	cd $inst
	[ -d "$clean" ] || $try \mkdir "$clean/$f"
	[ -d "$clean" ] || echo_red "**ERROR: $clean does not exist; exit"
	[ -d "$clean" ] || exit 2
	# do not move contrib/ as all examples are right there
	[ 0 -lt "$optx" ] && set -x
	for f in $files_info $files_ancient $files_develop $files_install_cgi $files_install_doc ; do
		[ -e "$clean/$f" ] && $try \rm -f "$clean/$f"
		[ -e "$f" ]        && $try \mv "$f" "$clean"
	done
	exit 0
fi; # clean mode }

# ------------------------- install mode  -------- {
if [ "$mode" = "dest" ]; then
	if [ ! -d "$inst" ]; then
		echo_red "**ERROR: $inst does not exist; exit"
		[ "$try" = "echo" ] || exit 2
	fi

	[ 0 -lt "$optx" ] && set -x
	echo "# remove old files ..."
	# TODO: argh, hard-coded list of files ...
	for f in $files_install $files_install_cgi $files_install_doc ; do
		f="$inst/$f"
		if [ -e "$f" ]; then
			$try \rm -f "$f" || exit 3
		fi
	done

	echo "# installing ..."
	$try \mkdir -p "$inst/Net"
	$try \mkdir -p "$inst/OSaft/Doc"
	for f in $files_install $files_install_cgi $files_install_doc ; do
		$try \cp "$f" "$inst/$f"  || exit 4
	done

	if [ $force -eq 1 ]; then
		$try \cp .$osaft_exe  "$inst/"        || echo_red ".$osaft_exe  failed"
		$try \cp contrib/.$osaft_gui "$inst/" || echo_red ".$osaft_gui failed"
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
#[ 0 -lt "$optx" ] && set -x    # - not used here

cd $inst

err=0

echo ""
echo "# check installation in $inst"
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
echo "# check for installed O-Saft in $inst"
echo "#--------------------------------------------------------------"
for o in $osaft_exe $osaft_gui ; do
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
for p in `echo $inst $HOME $PATH|tr ':' ' '` ; do
	rc="$p/.$osaft_exe"
	if [ -e "$rc" ]; then
		echo -n "# $rc\t" && echo_yellow "will be used when started in $p only"
	fi
done
rc="$HOME/.$osaft_gui"
if [ -e "$rc" ]; then
	v=`awk '/RCSID/{print $3}' $rc | tr -d '{};'`
	echo -n "# found $rc\t"   && echo_green "$v"
	echo -n "# exist $rc\t"   && echo_yellow "consider updating from contrib/.$osaft_gui"
else
	echo -n "# miss. $rc\t"   && echo_yellow "consider copying contrib/.$osaft_gui into your HOME directory: $HOME"
fi
echo "#--------------------------------------------------------------"

echo ""
echo "# check for installed Perl modules"
echo "#--------------------------------------------------------------"
modules="Net::DNS Net::SSLeay IO::Socket::SSL 
	 Net::SSLinfo Net::SSLhello osaft OSaft::error_handler OSaft::Doc::Data"
for m in $modules ; do
	echo -n "# testing for $m ...\t"
	# NOTE: -I . used to ensure that local ./Net is found
	v=`perl -I . -M$m -le 'printf"\t%s",$'$m'::VERSION' 2>/dev/null`
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
exit
echo "#--------------------------------------------------------------"

echo ""
echo "# check for important Perl modules used by O-Saft"
echo "#--------------------------------------------------------------"
modules="Net::DNS Net::SSLeay IO::Socket::SSL"
for p in `echo $PATH|tr ':' ' '` ; do
	o="$p/$osaft_exe"
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
	o="$p/$osaft_exe"
	r="$p/.$osaft_exe"
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

