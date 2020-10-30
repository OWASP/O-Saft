#! /bin/sh
#?
#? File generated from Makefile 1.102
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
#?          /path/to/installation/directory
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
#?          --expected  - show sample output expected for  --check
#                         All lines starting with #= are the sample output.
#?          --checkdev  - check system for development (make) requirements
#=
#=# check installation in /opt/o-saft
#=# (warnings are ok if 'git clone' will be used for development)
#=#--------------------------------------------------------------
#=#--------------------------------------------------------------
#=
#=# check for installed O-Saft in /opt/o-saft
#=#----------------------+---------------------------------------
#=#            ./o-saft.pl	19.08.19
#=#  /opt/0-saft/o-saft.pl	19.08.19
#=#           ./o-saft.tcl	1.219
#=# /opt/0-saft/o-saft.tcl	1.219
#=#----------------------+---------------------------------------
#=
#=# check for installed O-Saft resource files
#=#----------------------+---------------------------------------
#=#           ./.o-saft.pl	will be used when started in . only
#=# /opt/o-saft/.o-saft.pl	will be used when started in /opt/o-saft only
#=# /home/user/.o-saft.tcl	missing, consider generating: o-saft.tcl --rc > /home/user/.o-saft.tcl
#=#----------------------+---------------------------------------
#=
#=# check for installed Perl modules
#=#----------------------+---------------------------------------
#=#              Net::DNS	     1.2 /usr/local/share/perl/5.24.1/Net/DNS.pm
#=#           Net::SSLeay	    1.85 /usr/local/lib/x86_64-linux-gnu/perl/5.24.1/Net/SSLeay.pm
#=#       IO::Socket::SSL	   2.044 /usr/share/perl5/IO/Socket/SSL.pm
#=#           Time::Local	  1.2300 /usr/share/perl/5.24/Time/Local.pm
#=#          Net::SSLinfo	19.07.19 Net/SSLinfo.pm
#=#         Net::SSLhello	18.06.03 Net/SSLhello.pm
#=#                 osaft	19.07.29 osaft.pm
#=#  OSaft::error_handler	18.03.18 OSaft/error_handler.pm
#=#      OSaft::Doc::Data	19.07.29 OSaft/Doc/Data.pm
#=#----------------------+---------------------------------------
#=
#=# check for important Perl modules used by installed O-Saft
#=#----------------------+---------------------------------------
#=# testing /opt/o-saft/o-saft.pl ...	
#=#              Net::DNS 1.2 /usr/local/share/perl/5.24.1/Net/DNS.pm
#=#           Net::SSLeay 1.85 /usr/local/lib/x86_64-linux-gnu/perl/5.24.1/Net/SSLeay.pm
#=#       IO::Socket::SSL 2.044 /usr/share/perl5/IO/Socket/SSL.pm
#=#----------------------+---------------------------------------
#=
#=# summary of warnings from installed O-Saft (should be empty)
#=#----------------------+---------------------------------------
#=# testing /opt/o-saft/o-saft.pl in /opt/o-saft ...	
#=#----------------------+---------------------------------------
#=
#=# check for openssl executable in PATH
#=#--------------+-----------------------------------------------
#=# openssl:	/usr/bin/openssl (OpenSSL 1.1.0k  28 May 2019)
#=#--------------+-----------------------------------------------
#=
#=# check for openssl executable used by O-Saft
#=#--------------+-----------------------------------------------
#=# ./o-saft.pl:	/usr/local/openssl/bin/openssl (1.0.2k-dev) 
#=# /opt/o-saft/o-saft.pl:	/usr/local/openssl/bin/openssl (1.0.2k-dev) 
#=#--------------+-----------------------------------------------
#=
#=# check for contributed files
#=# (in /opt/o-saft/contrib )
#=#--------------+-----------------------------------------------
#=# found  	/opt/o-saft/contrib/Cert-beautify.awk
#=# found  	/opt/o-saft/contrib/Cert-beautify.pl
#=# found  	/opt/o-saft/contrib/HTML-simple.awk
#=# found  	/opt/o-saft/contrib/HTML-table.awk
#=# found  	/opt/o-saft/contrib/JSON-array.awk
#=# found  	/opt/o-saft/contrib/JSON-struct.awk
#=# found  	/opt/o-saft/contrib/XML-attribute.awk
#=# found  	/opt/o-saft/contrib/XML-value.awk
#=# found  	/opt/o-saft/contrib/bash_completion_o-saft
#=# found  	/opt/o-saft/contrib/bunt.pl
#=# found  	/opt/o-saft/contrib/bunt.sh
#=# found  	/opt/o-saft/contrib/cipher_check.sh
#=# found  	/opt/o-saft/contrib/dash_completion_o-saft
#=# found  	/opt/o-saft/contrib/filter_examples
#=# found  	/opt/o-saft/contrib/fish_completion_o-saft
#=# found  	/opt/o-saft/contrib/lazy_checks.awk
#=# found  	/opt/o-saft/contrib/tcsh_completion_o-saft
#=# found  	/opt/o-saft/contrib/usage_examples
#=# found  	/opt/o-saft/contrib/zap_config.sh
#=# found  	/opt/o-saft/contrib/zap_config.xml
#=#--------------+-----------------------------------------------
#=
#=# checks	passed
#?
#? OPTIONS
#?      --h     got it
#       --help  got it
#?      --n     do not execute, just show (ignored for  --check)
#?      -x      debug using shell's "set -x"
#?      --force install RC-FILEs  .o-saft.pl  and  .o-saft.tcl  in  $HOME,
#?              overwrites existing ones
#?      --no-colour         do not use coloured texts; default
#?      --colour            use coloured texts (red, yellow, blue|green)
#?      --colour-blind      same as --colour
#?      --colour-not-blind  use green instead of blue coloured texts
#?
#? EXAMPLES
#?      $0
#?      $0 --clean
#?      $0 --check
#?      $0 --install
#?      $0 /opt/bin/
#?      $0 /opt/bin/ --force
#?      $0 --install /opt/bin/
#?      $0 --check   /opt/bin/
#?
# HACKER's INFO
#       This file is generated from INSTALL-template.sh .
#       The generator (make) inserts most values for internal variables.  In
#       particular the list of source files to be installed. See the strings
#       and scopes containing  "generated from Makefile 1.102" .
#
#       All output is pretty printed. Yes, this adds some complexity, but it
#       is assumed that mainly humans read the output.
#
#       Environment variable inst can be set to installation directory: This
#       is useful for development only, hence not officially documented.
#           env inst=. $0 --check
#
#       Silently accepts the options  -n  or  -h  or  --x  also.
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
#?          awk, cat, perl, sed, tr, which, /bin/echo
#?
#? VERSION
#?      @(#) `)Q��U 1.50 20/10/30 15:36:56
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
colour=""       # 32 green, 34 blue for colour-blind
force=0
optx=0
optn=""
mode="";        # "", check, clean, dest, openssl
alias echo=/bin/echo    # need special echo which has -n option;
	        # TODO: check path for each platform
tab="	"       # need a real TAB (0x09) for /bin/echo

text_miss=" missing, try installing with ";
text_dev="did you run »$0 --clean«?"
text_alt="file from previous installation, try running »$0 --clean« "
text_old="ancient module found, try installing newer version, at least "

# generated from Makefile 1.102 {
osaft_exe="o-saft.pl"
osaft_gui="o-saft.tcl"
contrib_dir="contrib"
inst_directory=${inst:="/usr/local/o-saft"}

files_contrib="
	contrib/Cert-beautify.awk contrib/Cert-beautify.pl contrib/Dockerfile.alpine-3.6 contrib/HTML-simple.awk contrib/HTML-table.awk contrib/INSTALL-template.sh contrib/JSON-array.awk contrib/JSON-struct.awk contrib/XML-attribute.awk contrib/XML-value.awk contrib/bash_completion_o-saft contrib/bunt.pl contrib/bunt.sh contrib/cipher_check.sh contrib/critic.sh contrib/dash_completion_o-saft contrib/distribution_install.sh contrib/filter_examples contrib/fish_completion_o-saft contrib/gen_standalone.sh contrib/install_openssl.sh contrib/install_perl_modules.pl contrib/lazy_checks.awk contrib/symbol.pl contrib/tcsh_completion_o-saft contrib/usage_examples contrib/zap_config.sh contrib/zap_config.xml
		"

files_install="
	.o-saft.pl Dockerfile Net/SSLhello.pm Net/SSLinfo.pm OSaft/Ciphers.pm OSaft/Doc/Data.pm OSaft/Doc/coding.txt OSaft/Doc/glossary.txt OSaft/Doc/help.txt OSaft/Doc/links.txt OSaft/Doc/misc.txt OSaft/Doc/rfc.txt OSaft/Doc/tools.txt OSaft/error_handler.pm checkAllCiphers.pl o-saft o-saft-dbx.pm o-saft-docker o-saft-docker-dev o-saft-img.tcl o-saft-man.pm o-saft-usr.pm o-saft.pl o-saft.tcl osaft.pm
		"

files_install_cgi="
	docs/o-saft.cgi.html o-saft.cgi o-saft.php
		"

files_install_doc="
	docs/o-saft.1 docs/o-saft.html docs/o-saft.pod
		"
# generated from Makefile 1.102 }

# HARDCODED {
# because newer Makefiles may no longer know about them

files_ancient="
	generate_ciphers_hash openssl_h-to-perl_hash o-saft-README
	INSTALL-devel.sh .perlcriticrc o-saft_bench
	contrib/.o-saft.tcl contrib/o-saft.cgi contrib_dir/o-saft.php
	"

# first, dirty hack to make tests in development mode possible
# remember the inserted " to avoid substitutions here
[ "OSAFT_PL_INSERTED_""BY_MAKE"   = "$osaft_exe"   ]  && osaft_exe=o-saft.pl
[ "OSAFT_GUI_INSERTED_""BY_MAKE"  = "$osaft_gui"   ]  && osaft_gui=o-saft.tcl
[ "CONTRIBDIR_INSERTED_""BY_MAKE" = "$contrib_dir" ]  && contrib_dir=contrib

# some files "not to be installed" are ancient, they are kept here in
# $files_not_installed to ensure that outdated content is also handled
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
	[ -z "$colour" ] && echo "$@" && return
	\echo "\033[1;33m$@\033[0m"
}
echo_green  () {
	[ -z "$colour" ] && echo "$@" && return
	\echo "\033[1;$colour$@\033[0m"
}
echo_red    () {
	[ -z "$colour" ] && echo "$@" && return
	\echo "\033[1;31m$@\033[0m"
}

# --------------------------------------------- arguments and options
while [ $# -gt 0 ]; do
	case "$1" in
	 '-h' | '--h' | '--help' | '-?')
		\sed -ne "s/\$0/$ich/g" -e '/^#?/s/#?//p' $0
		exit 0
		;;
	 '-n' | '--n')          optn="--n"; try=echo; ;;
	 '-x' | '--x')          optx=1;       ;;
	  '--check')            mode=check;   ;;
	  '--clean')            mode=clean;   ;;
	  '--install')          mode=dest;    ;;
	  '--openssl')          mode=openssl; ;;
	  '--expected')         mode=expected; ;;
	  '--checkdev')         mode=checkdev; ;;
	  '--check-dev')        mode=checkdev; ;;
	  '--force')            force=1;      ;;
          '--no-colour')        colour="";    ;;
          '--colour')           colour="34m"; ;;
          '--colour-blind')     colour="34m"; ;;
          '--colour-not-blind') colour="32m"; ;;
          '--no-color')         colour="";    ;; # alias
          '--color')            colour="34m"; ;; # alias
          '--color-blind')      colour="34m"; ;; # alias
          '--color-not-blind')  colour="32m"; ;; # alias
          '---blind')           colour="34m"; ;; # alias
	  '--version')
		\sed -ne '/^#? VERSION/{' -e n -e 's/#?//' -e p -e '}' $0
		exit 0
		;;
	  '+VERSION')   echo 1.50 ; exit;      ;; # for compatibility to $osaft_exe
	  *)            inst_directory="$1";  ;; # directory, last one wins
	esac
	shift
done
clean_directory="$inst_directory/.files_to_be_removed"  # set on command line

# --------------------------------------------- main

# ------------------------- default mode --------- {
if [ -z "$mode" ]; then
	cat << EoUsage

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

# To get a sample of the expected output for  --check , use:

	$0 --expected

# To check development requirements, use:

	$0 --checkdev

# In a Docker image, this script may only be called like:

	$0 --check

EoUsage
	exit 0
fi; # default mode }

if [ "$mode" != "check" ]; then
	if [ -n "$osaft_vm_build" ]; then
	    echo "**ERROR: found 'osaft_vm_build=$osaft_vm_build'"
	    echo_red "**ERROR: inside docker only --check possible; exit"
	    exit 6
	fi
fi

# ------------------------ expected mode --------- {
if [ "$mode" = "expected" ]; then
	echo "## Expected output (sample) when called like:"
	echo "##     $0 --check /opt/o-saft"
	\sed -ne '/^#=/s/#=//p' $0
	exit 0
fi; # expected mode }

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
	files="$files_info $files_ancient $files_develop $files_install_cgi $files_install_doc $files_not_installed"
	for f in $files ; do
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
	if [ -z "$try" ]; then
		$try $inst_directory/$osaft_gui --rc > "$inst_directory/$osaft_guirc" \
		|| echo_red "**ERROR: generating $osaft_guirc failed"
	else
		echo "$inst_directory/$osaft_gui --rc > $inst_directory/$osaft_guirc"
	fi

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

# ------------------------- checkdev mode -------- {
tools_mandatory="ctags tags diff gpg sccs sha256sum docker perldoc"
tools_optional="aha cloc perl-analyzer perl-analyzer-output perlcritic
	podchecker podman podviewer tkpod
	mgdiff tkdiff xxdiff
	sslscan sslscan-1.11.9 testssl.sh"
	# $(LIST.legacy)
tools_modules="Data::Dumper File::Find Devel::Trace Debug::Trace
	Perl::Analyzer JSON Text::MicroTemplate GraphViz2 Storable
	Devel::DProf Devel::NYTProf"
# TODO: Devel::DProf Devel::NYTProf und GraphViz2  liefern Fehler auch wenn installiert
if [ "$mode" = "checkdev" ]; then
	echo ""
	echo "# check system for development usage"
	echo ""
	echo "# check for tools used with/in make targets"
	echo "#----------------------+---------------------------------------"
	for t in $tools_mandatory ; do
		is=`which $t`
		if [ -n "$is" ] ; then
			echo -n "# found  $tab" && echo_green  "$t$tab$is"
		else
			echo -n "# missing$tab" && echo_red    "$t"
		fi
	done
	for t in $tools_optional ; do
		is=`which $t`
		if [ -n "$is" ] ; then
			echo -n "# found  $tab" && echo_green  "$t$tab$is"
		else
			echo -n "# missing$tab" && echo_yellow "$t"
		fi
	done
	echo "#----------------------+---------------------------------------"
	echo ""
	echo "# check for Perl modules used with/in make targets"
	echo "#----------------------+---------------------------------------"
	for m in $tools_modules ; do
		perl -le "printf'# %21s',$m"    # use perl instead of echo for formatting
		# NOTE: -I . used to ensure that local ./Net is found
		v=`perl -I . -M$m -le 'printf"\t%8s",$'$m'::VERSION' 2>/dev/null`
		if [ -n "$v" ]; then
			echo_green  "$v"
		else 
			echo_red "${tab}missing; install with: 'cpan $m'"
			err=`expr $err + 1`
		fi
	done
	echo "#----------------------+---------------------------------------"
	exit 0
fi; # checkdev mode }

# ------------------------- check mode ----------- {
if [ "$mode" != "check" ]; then
	echo_red "**ERROR: unknow mode  $mode; exit"
	exit 5
fi

# all following is mode "check"
#[ 0 -lt "$optx" ] && set -x    # - not used here

[ -n "$optn"  ] && echo cd "$inst_directory"
cd "$inst_directory"

err=0

echo ""
echo "# check installation in $inst_directory"
echo "# (warnings are ok if 'git clone' will be used for development)"
echo "#--------------------------------------------------------------"
# err=`expr $err + 1` ; # errors not counted here
for f in $files_ancient ; do
	[ -e "$f" ] && echo -n "# found $f ...$tab" && echo_yellow "$text_alt"
done
for f in $files_develop $files_info ; do
	[ -e "$f" ] && echo -n "# found $f ...$tab" && echo_yellow "$text_dev"
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

# from here on, all **WARNINGS (from $osaft_exe) are unimportant  and hence
# redirected to /dev/null

echo ""
echo "# check for installed Perl modules"
echo "#----------------------+---------------------------------------"
modules="Net::DNS Net::SSLeay IO::Socket::SSL Time::Local
	 Net::SSLinfo Net::SSLhello osaft OSaft::error_handler OSaft::Doc::Data"
for m in $modules ; do
	perl -le "printf'# %21s',$m"    # use perl instead of echo for formatting
	# NOTE: -I . used to ensure that local ./Net is found
	v=`perl -I . -M$m -le 'printf"\t%8s",$'$m'::VERSION' 2>/dev/null`
	p=`perl -I . -M$m -le 'my $idx='$m';$idx=~s#::#/#g;printf"%s",$INC{"${idx}.pm"}' 2>/dev/null`
	if [ -n "$v" ]; then
		case "$m" in
		  'IO::Socket::SSL') expect=1.90; ;; # 1.37 and newer work, somehow ...
		  'Net::SSLeay')     expect=1.49; ;; # 1.33 and newer may work
		  'Net::DNS')        expect=0.80; ;;
		  'Time::Local')     expect=1.90; ;;
		esac
		case "$m" in
		  'Net::SSLinfo' | 'Net::SSLhello') c="green"; ;;
		  'OSaft::error_handler' | 'osaft') c="green"; ;;
		  'OSaft::Ciphers' )                c="green"; ;;
		  'OSaft::Doc::Data' )              c="green"; ;;
		  'Time::Local')
			# needs ugly hack :-((
			if [ 1.25 = $v ]; then
				# 1.25 seems to be newer than 1.230 which is newer than 1.90
				c="green";
			else
				c=`echo $expect $v | perl -anle '($e=$F[0])=~s#(\d+)#sprintf"%05d",$1#ge;($v=$F[1])=~s#(\d+)#sprintf"%05d",$1#ge;print (($e > $v) ? "red" : "green")'`; 
			fi
			;;
		  *) c=`echo $expect $v | perl -anle '($e=$F[0])=~s#(\d+)#sprintf"%05d",$1#ge;($v=$F[1])=~s#(\d+)#sprintf"%05d",$1#ge;print (($e > $v) ? "red" : "green")'`; ;;
		   # NOTE: need to compare for example: 1.23 > 1.230
		   # Comparing version strings is tricky,  best method would be
		   # to use Perl's Version module.  But this script should work
		   # on limited systems too, hence above cumbersome code: 
		   # 1. get the version strings on stdin
		   # 2. convert all number parts of the string to fixed 5-digit
		   #    format with leading zeros:  1.230 > 00001.000230
		   # 3. compare converted strings
		   #    Perl is clever enough to handle 00001.00023.42000  also
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
for p in `echo $inst_directory $PATH|tr ':' ' '` ; do
	o="$p/$osaft_exe"
	[ -e "$o" ] || continue
	# NOTE: output format is slightly different, 'cause **WARNINGS are printed too
	echo "# testing $o ...$tab"
	for m in $modules ; do
		perl -le "printf'# %21s',$m"
		w=`$o --no-warn +version 2>&1        | awk '/WARNING.*'$m'/{print}'`
		v=`$o --no-warn +version 2>/dev/null | awk '($1=="'$m'"){$1="";print}'`
		if [ -n "$w" ]; then
			echo_red    "$v"
			echo_yellow "$w"
		else
			echo_green  "$v"
		fi
		#err=`expr $err + 1`    # already counted in previous check
	done
done
echo "#----------------------+---------------------------------------"

echo ""
echo "# summary of warnings from installed O-Saft (should be empty)"
echo "#----------------------+---------------------------------------"
o="$inst_directory/$osaft_exe"
if [ -e "$o" ]; then
	echo "# testing $o in $inst_directory ...$tab"
	cd "$inst_directory"
	w=`$o +version 2>&1 | awk '/WARNING:/{print}'`
	[ -n "$w" ] && echo_yellow "$w"
fi
echo "#----------------------+---------------------------------------"

echo ""
echo "# check for openssl executable in PATH"
echo "#--------------+-----------------------------------------------"
echo -n "# openssl:$tab"    && echo_green "`which openssl`" "(`openssl version`)"
# TODO: warning when openssl missing
# TODO: error when openssl older than 0x01000000 has no SNI
echo "#--------------+-----------------------------------------------"

echo ""
echo "# check for openssl executable used by O-Saft"
echo "#--------------+-----------------------------------------------"
# TODO: error when openssl missing
for p in `echo $inst_directory $PATH|tr ':' ' '` ; do
	o="$p/$osaft_exe"
	r="$p/.$osaft_exe"
	if [ -x "$o" ]; then
		(
		cd "$p" # ensure that $r is used
		openssl=`$o --no-warn +version 2>/dev/null | awk '/external executable/{print $NF}' | tr '\012' ' '`
		echo -n "# $o:$tab" && echo_green "$openssl"
		)
	fi
done
echo "#--------------+-----------------------------------------------"

echo ""
echo "# check for contributed files"
echo "# (in $inst_directory/$contrib_dir )"
echo "#--------------+-----------------------------------------------"
for c in $files_contrib ; do
	skip=0
	for f in $files_not_installed $files_develop ; do
		[ "$f" = "$c" ] && skip=1
	done
	[ $skip -eq 1 ] && continue
	c="$inst_directory/$c"
	if [ -e "$c" ]; then
		echo -n "# found  $tab" &&
		echo_green  "$c"
	else
		echo -n "# missing$tab" &&
		echo_yellow "$c"
		#err=`expr $err + 1`    # not counted as error
	fi
done
echo "#--------------+-----------------------------------------------"

echo ""
echo -n "# checks$tab"
if [ $err -eq 0 ]; then
	echo_green "passed"
else
	echo_red   "failed , $err error(s) detected"
fi

# check mode }

exit $err

