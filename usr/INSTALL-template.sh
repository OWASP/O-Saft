#! /bin/sh
#?
#? File INSERTED_BY_MAKE_FROM
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
#?                        default if no other option given
#?          --check     - check current installation
#?          --clean     - move files not necessary to run O-Saft into subdir
#?                        ./.files_to_be_removed
#                This is the behaviour of the old  INSTALL-devel.sh  script.
#?          --openssl   - calls  contrib/install_openssl.sh which builds and
#?                        installs  openssl  and  Net::SSLeay ; this doesn't
#?                        support other options and arguments of
#?                        contrib/install_openssl.sh
#?          --cgi       - prepare directory to be used in CGI mode
#?          --expected  - show sample output expected for  --check
#                         All lines starting with #= are the sample output.
#?          --checkdev  - check system for development (make) requirements
#=
#=# check for O-Saft programs found via environment variable PATH
#=#--------------------------------------------------------------
#=#                  wish	/usr/bin
#=#             o-saft.pl	not found in PATH, consider adding /opt/o-saft to PATH
#=#            o-saft.tcl	not found in PATH, consider adding /opt/o-saft to PATH
#=#                o-saft	not found in PATH, consider adding /opt/o-saft to PATH
#=# Note: all found executables in PATH are listed
#=#--------------------------------------------------------------
#=
#=# check installation in /opt/o-saft
#=#--------------------------------------------------------------
#=# (warnings are ok if »git clone« will be used for development)
#=#            Dockerfile	found; did you run »INSTALL.sh --clean«?
#=#              Makefile	found; did you run »INSTALL.sh --clean«?
#=#                    t/	found; did you run »INSTALL.sh --clean«?
#=#     contrib/critic.sh	found; did you run »INSTALL.sh --clean«?
#=#               CHANGES	found; did you run »INSTALL.sh --clean«?
#=#                README	found; did you run »INSTALL.sh --clean«?
#=#--------------------------------------------------------------
#=
#=# check for used O-Saft programs (according $PATH)
#=#----------------------+---------------------------------------
#=#             o-saft.pl	22.11.22 /opt/o-saft/o-saft.pl
#=#            o-saft.tcl	    2.35 /opt/o-saft/o-saft.tcl
#=#                o-saft	    1.26 /opt/o-saft/o-saft
#=# contrib/o-saft-standalone.pl 22.11.22 contrib/o-saft-standalone.pl
#=#----------------------+---------------------------------------
#=
#=# check for installed O-Saft resource files
#=#----------------------+---------------------------------------
#=#          ./.o-saft.pl	will be used when started in . only
#=# /opt/o-saft/.o-saft.pl	will be used when started in /opt/o-saft only
#=# /home/usr/.o-saft.tcl	missing, consider generating: »o-saft.tcl --rc > /home/user/.o-saft.tcl«
#=#----------------------+---------------------------------------
#=
#=# check for installed Perl modules (started in '$inst_directory')
#=#----------------------+---------------------------------------
#=#              Net::DNS	    1.29 /usr/local/share/perl/5.24.1/Net/DNS.pm
#=#           Net::SSLeay	    1.88 /usr/local/lib/x86_64-linux-gnu/perl/5.24.1/Net/SSLeay.pm
#=#      IO::Socket::INET	    1.41 /usr/local/lib/x86_64-linux-gnu/perl-base/IO/Socket/INET.pm
#=#                                      ancient module found, try installing newer version, at least  1.49
#=#       IO::Socket::SSL	   2.069 /usr/share/perl5/IO/Socket/SSL.pm
#=#           Time::Local	    1.28 /usr/share/perl/5.28/Time/Local.pm
#=#                  OCfg	24.01.24 lib/OCfg.pm
#=#               Ciphers	24.01.24 lib/Ciphers.pm
#=#         error_handler	24.01.24 lib/error_handler.pm
#=#               SSLinfo	24.01.24 lib/SSLinfo.pm
#=#              SSLhello	24.01.24 lib/SSLhello.pm
#=#                 OData	24.01.24 lib/OData.pm
#=#                  ODoc	24.01.24 lib/ODoc.pm
#=#                  OMan	24.01.24 lib/OMan.pm
#=#                 OText	24.01.24 lib/OText.pm
#=#                OTrace	24.01.24 lib/OTrace.pm
#=#                  OUsr	24.01.24 lib/OUsr.pm
#=#----------------------+---------------------------------------
#=
#=# check for important Perl modules used by installed O-Saft
#=#----------------------+---------------------------------------
#=# testing /opt/o-saft/o-saft.pl ...	
#=#              Net::DNS	    1.29 /usr/local/share/perl/5.24.1/Net/DNS.pm
#=#           Net::SSLeay	    1.88 /usr/local/lib/x86_64-linux-gnu/perl/5.24.1/Net/SSLeay.pm
#=#      IO::Socket::INET	    1.41 /usr/local/lib/x86_64-linux-gnu/perl-base/IO/Socket/INET.pm
#=#       IO::Socket::SSL	   2.069 /usr/share/perl5/IO/Socket/SSL.pm
#=#           Time::Local	    1.28 /usr/share/perl/5.28/Time/Local.pm
#=# testing /opt/o-saft/o-saft.pl in /opt/o-saft ...	
#=#              Net::DNS	    1.29 /usr/local/share/perl/5.24.1/Net/DNS.pm
#=#           Net::SSLeay	    1.88 /usr/local/lib/x86_64-linux-gnu/perl/5.24.1/Net/SSLeay.pm
#=#       IO::Socket::SSL	   2.069 /usr/share/perl5/IO/Socket/SSL.pm
#=#           Time::Local	    1.28 /usr/share/perl/5.28/Time/Local.pm
#=#----------------------+---------------------------------------
#=
#=# summary of warnings from installed O-Saft (should be empty)
#=#----------------------+---------------------------------------
#=# testing /opt/o-saft/o-saft.pl in /opt/o-saft ...	
#=#----------------------+---------------------------------------
#=
#=# check for openssl executable in PATH
#=#----------------------+---------------------------------------
#=#               openssl	/usr/bin/openssl (OpenSSL 1.1.1n  15 Mar 2022)
#=#----------------------+---------------------------------------
#=
#=# check for openssl executable used by O-Saft
#=#----------------------+---------------------------------------
#=#           ./o-saft.pl	/usr/local/openssl/bin/openssl (1.0.2k-dev) 
#=# /opt/o-saft/o-saft.pl	/usr/local/openssl/bin/openssl (1.0.2k-dev) 
#=#----------------------+---------------------------------------
#=
#=# check for optional tools to view documentation
#=#----------------------+---------------------------------------
#=#                   aha	/usr/bin/aha
#=#               perldoc	/usr/bin/perldoc
#=#              pod2html	/usr/bin/pod2html
#=#               pod2man	/usr/bin/pod2man
#=#              pod2text	/usr/bin/pod2text
#=#             pod2usage	/usr/bin/pod2usage
#=#                podman	missing
#=#             podviewer	/usr/bin/podviewer
#=#                  stty	/bin/stty
#=#                 tkpod	/usr/bin/tkpod
#=#                  tput	/usr/bin/tput
#=#
#=# Note: podman is a tool to view pod files, it's not the container engine
#=#----------------------+---------------------------------------
#=
#=# check for contributed files (in /opt/o-saft/contrib )
#=#----------------------+---------------------------------------
#=#     Cert-beautify.awk	/opt/o-saft/contrib/Cert-beautify.awk
#=#      Cert-beautify.pl	/opt/o-saft/contrib/Cert-beautify.pl
#=#       HTML-simple.awk	/opt/o-saft/contrib/HTML-simple.awk
#=#        HTML-table.awk	/opt/o-saft/contrib/HTML-table.awk
#=#        JSON-array.awk	/opt/o-saft/contrib/JSON-array.awk
#=#       JSON-struct.awk	/opt/o-saft/contrib/JSON-struct.awk
#=#     XML-attribute.awk	/opt/o-saft/contrib/XML-attribute.awk
#=#         XML-value.awk	/opt/o-saft/contrib/XML-value.awk
#=#       alertscript.cfg	/opt/o-saft/contrib/alertscript.cfg
#=#        alertscript.pl	/opt/o-saft/contrib/alertscript.pl
#=# bash_completion_o-saft	/opt/o-saft/contrib/bash_completion_o-saft
#=#               bunt.pl	/opt/o-saft/contrib/bunt.pl
#=#               bunt.sh	/opt/o-saft/contrib/bunt.sh
#=#       cipher_check.sh	/opt/o-saft/contrib/cipher_check.sh
#=# dash_completion_o-saft	/opt/o-saft/contrib/dash_completion_o-saft
#=#       filter_examples	/opt/o-saft/contrib/filter_examples
#=# fish_completion_o-saft	/opt/o-saft/contrib/fish_completion_o-saft
#=#       lazy_checks.awk	/opt/o-saft/contrib/lazy_checks.awk
#=#             symbol.pl	/opt/o-saft/contrib/symbol.pl
#=# tcsh_completion_o-saft	/opt/o-saft/contrib/tcsh_completion_o-saft
#=#        usage_examples	/opt/o-saft/contrib/usage_examples
#=#         zap_config.sh	/opt/o-saft/contrib/zap_config.sh
#=#        zap_config.xml	/opt/o-saft/contrib/zap_config.xml
#=#  o-saft-standalone.pl	/opt/o-saft/contrib/o-saft-standalone.pl
#=#----------------------+---------------------------------------
#=
#=# checks	passed
#?
#? OPTIONS
#?      --h     got it
#       --help  got it
#?      --n     do not execute, just show (ignored for  --check)
#?      -x      debug using shell's "set -x"
#?      --force         - install  RC-FILEs  .o-saft.pl  and  .o-saft.tcl in
#?                        $HOME, overwrites existing ones
#?      --no-colour     - do not use coloured texts; default
#?      --colour        - use coloured texts (red, yellow, blue|green)
#?      --colour-blind  - same as --colour
#?      --colour-not-blind  - use green instead of blue coloured texts
#?      --other         - check for other SSL-related tool with  --checkdev
#?      --useenv        - change #! (shebang) lines to  #!/usr/bin/env
#?                        Applies only to files with following extensions:
#?                          .awk  .cgi .pl  .sh  .tcl  .txt
#?                        also applies to all Makefile* .
#?                        The shebang line  will only be changed when there
#?                        are no arguments given.
#?                        Examples of changed lines:
#?                            #!/bin/sh
#?                            #! /bin/sh
#?                            #!/bin/cat
#?                            #!/usr/bin/make
#?                            #!/usr/bin/perl
#?                        Examples of lines not to be changed:
#?                            #!/usr/bin/gawk -f
#?                            #!/usr/bin/make -rRf
#?                            #! /usr/bin/perl -w
#?                            #!/usr/bin/perl -w
#?                            #!/usr/bin/perl -w -I .
#?      --gnuenv        - change #! (shebang) lines to  #!/usr/bin/env -S
#?                        Applies the change to shebang lines with arguments.
#?                        Implies  --useenv .
#?
#?      Please see  docs/concepts.txt  for details about /usr/bin/env .
#?      It's up to user then, which solution fits better.
#?
#? EXAMPLES
#?      $0
#?      $0 --clean
#?      $0 --check
#?      $0 --install
#?      $0 /opt/bin/
#?      $0 /opt/bin/ --force
#?      $0 /opt/bin/ --useenv
#?      $0 /opt/bin/ --gnuenv
#?      $0 --install /opt/bin/
#?      $0 --check   /opt/bin/
#?      $0 --check   /opt/bin/ --colour
#?      $0 --checkdev
#?      $0 --cgi /opt/bin/
#?      $0 --cgi .
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
#?      @(#) INSTALL-template.sh 3.1 24/01/23 21:04:23
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
_break=0                # 1 if screen width < 50; then use two lines as output
colour=""               # 32 green, 34 blue for colour-blind
useenv=0                # 1 to change shebang lines to /usr/bin/env
gnuenv=0                # 1 to change shebang lines to /usr/bin/env -S
other=0
force=0
optx=0
optn=""
mode="";                # "", cgi, check, clean, dest, openssl
alias echo=/bin/echo    # need special echo which has -n option;
	                # TODO: check path for each platform
tab="	"               # need a real TAB (0x09) for /bin/echo

text_miss="missing, try installing from/with";
text_old="ancient module found, try installing newer version, at least "
text_one="missing, consider generating with »make standalone«"
text_path="Note: all found executables in PATH are listed"
text_prof="note: Devel::DProf Devel::NYTProf and GraphViz2 may wrongly be missing"
text_tool="Note: podman is a tool to view pod files, it's not the container engine"
# must be redefined after reading arguments
text_dev="did you run »$0 --clean«?"
text_alt="file from previous installation, try running »$0 --clean« "

# INSERTED_BY_MAKE {
osaft_sh="INSERTED_BY_MAKE_OSAFT_SH"
osaft_pm="INSERTED_BY_MAKE_OSAFT_PM"
osaft_exe="INSERTED_BY_MAKE_OSAFT_PL"
osaft_gui="INSERTED_BY_MAKE_OSAFT_GUI"
osaft_one="INSERTED_BY_MAKE_OSAFT_STAND"
osaft_dock="INSERTED_BY_MAKE_OSAFT_DOCKER"
contrib_dir="INSERTED_BY_MAKE_CONTRIBDIR"
inst_directory=${inst:="INSERTED_BY_MAKE_INSTALLDIR"}
perl_modules="INSERTED_BY_MAKE_PERL_MODULES"
osaft_subdirs="INSERTED_BY_MAKE_OSAFT_DIRS"
osaft_libdir="INSERTED_BY_MAKE_OSAFT_LIBDIR"

osaft_modules="
	INSERTED_BY_MAKE_OSAFT_MODULES
	"

files_contrib="
	INSERTED_BY_MAKE_CONTRIB
	"

files_install="
	INSERTED_BY_MAKE_OSAFT
	"

files_install_cgi="
	INSERTED_BY_MAKE_OSAFT_CGI
	"

files_install_doc="
	INSERTED_BY_MAKE_OSAFT_DOC
	"

tools_intern="
	INSERTED_BY_MAKE_DEVTOOLSINT
	"

tools_extern="
	INSERTED_BY_MAKE_DEVTOOLSEXT
	"

tools_modules="
	INSERTED_BY_MAKE_DEVMODULES
	"

tools_optional="
	INSERTED_BY_MAKE_TOOLS_OPT
	"

tools_other="
	INSERTED_BY_MAKE_TOOLS_OTHER
	"

# INSERTED_BY_MAKE }

# HARDCODED {
# because newer Makefiles may no longer know about them

files_ancient="
	generate_ciphers_hash openssl_h-to-perl_hash o-saft-README
	o-saft-dbx.pm o-saft-usr.pm
	INSTALL-devel.sh .perlcriticrc o-saft_bench
	contrib/.o-saft.tcl contrib/o-saft.cgi contrib_dir/o-saft.php
	"

# first, dirty hack to make tests in development mode possible
# remember the inserted "" to avoid substitutions here
[ "INSERTED_""BY_MAKE_OSAFT_SH"   = "$osaft_sh"     ] && osaft_sh=o-saft
[ "INSERTED_""BY_MAKE_OSAFT_PL"   = "$osaft_exe"    ] && osaft_exe=o-saft.pl
[ "INSERTED_""BY_MAKE_OSAFT_GUI"  = "$osaft_gui"    ] && osaft_gui=o-saft.tcl
[ "INSERTED_""BY_MAKE_OSAFT_DOCKER" = "$osaft_dock" ] && osaft_dock=o-saft-docker
[ "INSERTED_""BY_MAKE_CONTRIBDIR" = "$contrib_dir"  ] && contrib_dir=contrib

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
all_exe="$osaft_exe $osaft_gui $osaft_sh $osaft_dock $osaft_one"
    # checking INSTALL.sh (myself) is pointless, somehow ...

_line='----------------------+-----------------'
_cols=0
\command -v \tput >/dev/null && _cols=`\tput cols`
if [ 0 -lt $_cols ]; then
	# adapt _line to screen width
	[ -n "$OSAFT_MAKE" ] && _cols=78    # SEE Make:OSAFT_MAKE
	[ 51 -gt $_cols ] && _break=1       # see echo_label()
	while [ 42 -lt $_cols ]; do
		_line="$_line-"
		_cols=`expr $_cols - 1`
	done
fi

# --------------------------------------------- internal functions
echo_head   () {
	echo ""
	if [ -z "$colour" ]; then
		echo "$@"
		echo "#$_line"
	else
		\echo "\033[7;37m\033[1;30m$@"
		\echo "#$_line\033[0m"
	fi
}
echo_foot   () {
	if [ -z "$colour" ]; then
		echo "#$_line"
	else
		\echo "\033[7;37m\033[1;30m#$_line\033[0m"
	fi
}
echo_label  () {
	perl -le "printf'# %21s%c','$@',0x09"  # use perl instead of echo for formatting
	[ 0 -eq $_break ] && return
	perl -le 'printf"\n\t"'             # use additional line
}
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

check_pm    () {
	# check if passed name is own perl module; return 0 if it is own module
	# name can be path like Net/SSLinfo.pm or module name like  lib/SSLinfo
	# NOTE: extension in name (anything right of rightmost . including.) is
	#       removed; this assumes that module names  (wether perl syntax or
	#       path name) cannot contain . (dot).
	_m=$1
	_m=`\echo "$_m" | \sed -e 's#::#/#g'`
	_m=${_m%.*}     # remove extension (.pm) if any
	for _p in $osaft_pm ; do
		_p=${_p%.*}     # remove extension (.pm) if any
		[ "$_p" = "$_m" ] && return 0
	done
	return 1
}

check_commands () {
	for c in $* ; do
		echo_label "$c"
		is=`\command -v $c`
		[ -n "$is" ] && echo_green "$is" || echo_red "missing"
	done
	return
}

copy_file   () {
	src=$1
	dst=$2
	convert=0
	if [ 0 -lt $useenv ]; then
		ext=${src##*.}
		file=${src##*/}
		# ugly hardcode match of extensions and names
		case "$ext" in
		    awk | cgi | pl | pm | sh | tcl | pod | txt)  convert=1 ; ;;
		esac
		case "$file" in
		    o-saft)               convert=1 ; ;;
		    usage_examples)       convert=1 ; ;;
		    o-saft-docker*)       convert=1 ; ;;
		    Dockerfile*)          convert=1 ; ;;
		    Makefile*)            convert=1 ; ;;
		    *_completion_o-saft)  convert=1 ; ;;
		esac
	fi
	#dbx# \perl -lane 'if(1==$.){exit 1 if m|^#\!\s*/usr/bin/env |}' "$src" || echo skip $src ...
	\perl -lane 'if(1==$.){exit 1 if m|^#\!\s*/usr/bin/env |}' "$src" || convert=0
	if [ 1 -eq $convert ]; then
		# only the very first line $. ist changed
		if [ "$try" = "echo" ]; then
		    echo 'perl -lane "if(1==$.){s|^.*?/([a-zA-Z0-9_.-]+$)|#\!/usr/bin/env $1|;}print;" '"'$src' > '$dst'"
		    return
		fi
		# convert only  "#! /some/path/tool"
		\perl -lane 'if(1==$.){s|^.*?/([a-zA-Z0-9_.-]+)\s*$|#\!/usr/bin/env $1|;}print;' \
			"$src" > "$dst"  || exit 4
		if [ 0 -lt $gnuenv ]; then
		# convert only  "#! /some/path/tool arg..."
		\perl -lane 'if(1==$.){exit 1 if m|^#.*?/([a-zA-Z0-9_.-]+)\s(.*)$|;}' "$src" || \
		\perl -lane 'if(1==$.){s|^#.*?/([a-zA-Z0-9_.-]+)\s(.*)$|#\!/usr/bin/env -S $1 $2|;}print;' \
			"$src" > "$dst"  || exit 4
		fi
		# set proper modes
		\chmod 555 "$dst" # assuming that it is and should be executable

	else
		$try \cp --preserve=all "$src"  "$dst"  || exit 4
	fi
	return
}

# --------------------------------------------- arguments and options
new_dir=
while [ $# -gt 0 ]; do
	case "$1" in
	 '-h' | '--h' | '--help' | '-?')
		\sed -ne "s/\$0/$ich/g" -e '/^#?/s/#?//p' $0
		exit 0
		;;
	 '-n' | '--n')          optn="--n"; try=echo; ;;
	#			#	#	#
	 '-x' | '--x')          optx=1;         ;;
	  '--cgi')              mode=cgi;       ;;
	  '--check')            mode=check;     ;;
	  '--clean')            mode=clean;     ;;
	  '--install')          mode=dest;      ;;
	  '--openssl')          mode=openssl;   ;;
	  '--expect')           mode=expected;  ;; # alias
	  '--expected')         mode=expected;  ;;
	  '--checkdev')         mode=checkdev;  ;;
	  '--check-dev')        mode=checkdev;  ;;
	  '--force')            force=1;        ;;
	  '--other')            other=1;        ;;
          '--no-colour')        colour="";      ;;
          '--colour')           colour="34m";   ;;
          '--colour-blind')     colour="34m";   ;;
          '--colour-not-blind') colour="32m";   ;;
          '--no-color')         colour="";      ;; # alias
          '--color')            colour="34m";   ;; # alias
          '--color-blind')      colour="34m";   ;; # alias
          '--color-not-blind')  colour="32m";   ;; # alias
          '--bunt')             colour="34m";   ;; # alias
          '--blind')            colour="34m";   ;; # alias
          '--useenv')           useenv=1;       ;;
          '--use-env')          useenv=1;       ;; # alias
          '--gnuenv')           gnuenv=1; useenv=1; ;;
          '--gnu-env')          gnuenv=1; useenv=1; ;; # alias
	  '--version')
		\sed -ne '/^#? VERSION/{' -e n -e 's/#?//' -e p -e '}' $0
		exit 0
		;;
	  '+VERSION')   echo 3.1 ; exit;        ;; # for compatibility to $osaft_exe
	  *)            new_dir="$1"   ;        ;; # directory, last one wins
	esac
	shift
done
if [ -n "$new_dir" ]; then
	inst_directory="$new_dir"
	[ -z "$mode" ] && mode=dest              # no mode given, set default
fi
clean_directory="$inst_directory/.files_to_be_removed"  # set on command line
text_dev="did you run »$0 --clean $inst_directory«?"
text_alt="file from previous installation, try running »$0 --clean $inst_directory« "

# --------------------------------------------- main

# ------------------------ expected mode --------- {
if [ "$mode" = "expected" ]; then
	echo "## Expected output (sample) when called like:"
	echo "##     $0 --check /opt/o-saft"
	\sed -ne '/^#=/s/#=//p' $0
	exit 0
fi; # expected mode }

if [ '..' = "$dir" ]; then
	# avoid errors in $0 if called by own make
	[ "${OSAFT_MAKE:+1}"  ] && cd .. && echo "cd ..  # due to OSAFT_MAKE"
fi

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
	    echo "**ERROR: 001: found 'osaft_vm_build=$osaft_vm_build'"
	    echo_red "**ERROR: 002: inside docker only --check possible; exit"
	    exit 6
	fi
fi

# ------------------------ cgi mode -------------- {
if [ "$mode" = "cgi" ]; then
	echo "# prepare $inst_directory for use in CGI mode"
	if [ ! -d "$inst_directory" ]; then
		echo_red "**ERROR: 050: $inst_directory does not exist; exit"
		[ "$try" = "echo" ] || exit 2
		# with --n continue, so we see what would be done
	fi
	if [ -d "$clean_directory" ]; then
		echo_red "**ERROR: 051: $clean_directory exist; CGI installation not yet supported"
		exit 2
	fi
	for f in $files_install_cgi ; do
		file=${f##*/}
		[ -e "$inst_directory/$file" ] && echo -n "# " && echo_yellow "existing $file; ignored" && continue
		$try \mv $f "$inst_directory/" || echo_red "**ERROR: 052: moving $f failed"
	done
	lnk=cgi-bin
	[ -e "$inst_directory/$lnk" ] && echo -n "# " && echo_yellow "existing $lnk; ignored" && continue
	$try \ln -s "$inst_directory" $lnk  || echo_red "**ERROR: 053: symlink $lnk failed"
	exit 0
fi; # cgi mode }

# ------------------------- openssl mode --------- {
if [ "$mode" = "openssl" ]; then
	echo "# call $build_openssl"
	[ ! -x "$build_openssl" ] && echo_red "**ERROR: 020: $build_openssl does not exist; exit" && exit 2
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
#     $build_openssl /path/to/install --debian --i --m
EoT
	fi
	exit $status
fi; # openssl mode }

# ------------------------- clean mode ----------- {
if [ "$mode" = "clean" ]; then
	echo "# cleanup installation in $inst_directory"
	[ -d "$clean_directory" ] || $try \mkdir "$clean_directory/$f"
	[ -d "$clean_directory" ] || $try echo_red "**ERROR: 030: $clean_directory does not exist; exit"
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
		echo_red "**ERROR: 040: $inst_directory does not exist; exit"
		[ "$try" = "echo" ] || exit 2
		# with --n continue, so we see what would be done
	fi

	files="$files_install $files_install_cgi $files_install_doc $files_contrib $osaft_one"
	[ 0 -lt "$optx" ] && set -x
	echo "# remove old files ..."
	for f in $files ; do
		f="$inst_directory/$f"
		if [ -e "$f" ]; then
			$try \rm -f "$f" || exit 3
		fi
	done

	echo "# installing ..."
	for d in $osaft_subdirs ; do
		$try \mkdir -p "$inst_directory/$d"
	done
	for f in $files ; do
		[ -e "$f" ] || echo_red "**ERROR: 043: missing $f; file ignored"
		copy_file "$f" "$inst_directory/$f"
	done
	if [ -z "$try" ]; then
		w=$(\command -v wish)
		if [ -n "$osaft_gui" -a -n "$w" ]; then
			$try $inst_directory/$osaft_gui --rc > "$inst_directory/$osaft_guirc" \
			|| echo_red "**ERROR: 041: generating $osaft_guirc failed"
		else
			echo -n "# " && echo_yellow "missing wish; $osaft_guirc not installed"
		fi
	else
		echo "$inst_directory/$osaft_gui --rc > $inst_directory/$osaft_guirc"
	fi

	if [ $force -eq 1 ]; then
		echo '# installing RC-FILEs in $HOME ...'
		for f in $inst_directory/$osaft_exerc $inst_directory/$osaft_exerc ; do
			$try \cp $f "$HOME/" || echo_red "**ERROR: 042: copying $f failed"
		done
	fi

	echo    "# consider calling: $0 --clean $inst_directory"
	echo -n "# installation in $inst_directory "; echo_green "completed."
	exit 0
fi; # install mode }

# ------------------------- checkdev mode -------- {
if [ "$mode" = "checkdev" ]; then
	echo ""
	echo "# check system for development usage"
	echo_head "# check for tools used with/in make targets"
	check_commands $tools_intern
	check_commands $tools_extern
	echo "#"
	echo "# $text_tool"
	echo_foot
	echo_head "# check for Perl modules used with/in make targets"
	for m in $tools_modules ; do
		echo_label "$m"
		# NOTE: -I . used to ensure that local ./Net is found
		v=`perl -I . -M$m -le 'printf"%8s",$'$m'::VERSION' 2>/dev/null`
		if [ -n "$v" ]; then
			echo_green  "$v"
		else 
			echo_red "missing; install with: »cpan $m«"
			err=`expr $err + 1`
		fi
	done
	echo "#"
	echo "# $text_prof"
	echo_foot
	echo ""

	[ $other -eq 0 ] && exit 0;

	# printed with --other only
	echo_head "# check for other SSL-related tools"
	check_commands $tools_other
	echo_foot
	exit 0
fi; # checkdev mode }

# ------------------------- check mode ----------- {
if [ "$mode" != "check" ]; then
	echo_red "**ERROR: 060: unknow mode  $mode; exit"
	exit 5
fi

# all following is mode "check"
#[ 0 -lt "$optx" ] && set -x    # - not used here

cnt=0
gui=0
echo_head "# check for O-Saft programs found via environment variable PATH"
for p in `echo $PATH|tr ':' ' '` ; do
	for o in $all_exe wish ; do
		exe="$p/$o"
		if [ -e "$exe" ]; then
			cnt=`expr $cnt + 1`
			echo_label "$exe" && echo_green "$p"
			#echo_label "$exe" && echo_yellow "missing"
		fi
		[ "$o" != "wish" ] && continue
		if [ -e "$exe" ]; then
			gui=`expr $gui + 1`
			echo_label "wish" && echo_green "$p"
		fi
	done
done
echo "#"
echo "# $text_path"
[ 0 -eq $cnt   -o   0 -eq $gui ] && echo "#"
[ 0 -eq $cnt ]  && echo_label  "$osaft_exe" \
		&& echo_yellow "not found in PATH, consider adding $inst_directory to PATH"
[ 0 -eq $gui ]  && echo_label  "wish" \
		&& echo_yellow "not found in PATH, consider installing wish" \
		&& osaft_gui=
[ -e "$osaft_one" ] || ( echo_label "$osaft_one" && echo_yellow "$text_one" )
echo_foot

PATH=${inst_directory}:$PATH    # ensure that given directory is in PATH

[ -n "$optn"  ] && echo cd "$inst_directory"
cd "$inst_directory"

err=0

echo_head "# check installation in $inst_directory"
echo "# (warnings are ok if »git clone« will be used for development)"
# err=`expr $err + 1` ; # errors not counted here
for f in $files_ancient ; do
	[ -e "$f" ] && echo_label "$f" && echo_yellow "found; $text_alt"
done
for f in $files_develop $files_info ; do
	[ -e "$f" ] && echo_label "$f" && echo_yellow "found; $text_dev"
done
echo_foot

echo_head '# check for used O-Saft programs (according $PATH)'
for o in $all_exe ; do
	echo_label "$o"
	e=`\command -v $o`
	if [ -n "$e" ] ; then
		v=`$o +VERSION`
		txt=`echo "$v $e"|awk '{printf("%8s %s",$1,$2)}'`
		echo_green "$txt"
	else
		err=`expr $err + 1`
		echo_red   "not found"
	fi
done
echo_foot

echo_head "# check for installed O-Saft resource files"
# currently no version check
cnt=0
for p in `echo $HOME $PATH|tr ':' ' '` ; do
	rc="$p/$osaft_exerc"
	if [ -e "$rc" ]; then
		cnt=`expr $err + 1`
		echo_label "$rc" && echo_yellow "will be used when started in $p only"
	fi
done
[ 0 -eq $cnt ] && echo_yellow "$rc not found"
rc="$HOME/$osaft_guirc"
if [ -e "$rc" ]; then
	v=`awk '/RCSID/{print $3}' $rc | tr -d '{};'`
	echo_label "$rc" && echo_green  "$v"
	txt="ancient"
else
	txt="missing"
fi
echo_label "$rc" && echo_yellow "$txt, consider generating: »$osaft_gui --rc > $rc«"
echo_foot

# from here on, all **WARNINGS (from $osaft_exe) are unimportant  and hence
# redirected to /dev/null

echo_head "# check for installed Perl modules (started in $inst_directory )"
for m in $perl_modules $osaft_modules ; do
	echo_label "$m"
	text_cpan="»cpan $m«"
	v=`perl -I $osaft_libdir -M$m -le 'printf"%8s",$'$m'::VERSION' 2>/dev/null`
	p=`perl -I $osaft_libdir -M$m -le 'my $idx='$m';$idx=~s#::#/#g;printf"%s",$INC{"${idx}.pm"}' 2>/dev/null`
	if [ -n "$v" ]; then
		if check_pm "$m" ; then c="green"; fi
		case "$m" in
		  'IO::Socket::SSL') expect=1.90; ;; # 1.37 and newer work, somehow ...
		  'Net::SSLeay')     expect=1.49; ;; # 1.33 and newer may work
		  'Net::DNS')        expect=0.80; ;;
		  'Time::Local')     expect=1.90; ;;
		esac
		case "$m" in
		  'Time::Local')
			# has strange version numbering, needs ugly hack :-((
			if [ 1.25 = $v \
			  -o 1.26 = $v \
			  -o 1.27 = $v \
			  -o 1.28 = $v ]; then
				# 1.25 seems to be newer than 1.230 which is newer than 1.90
				c="green";
			else
				c=`echo $expect $v | perl -anle '($e=$F[0])=~s#(\d+)#sprintf"%05d",$1#ge;($v=$F[1])=~s#(\d+)#sprintf"%05d",$1#ge;print (($e > $v) ? "red" : "green")'`; 
			fi
			;;
		  *) # our own modules
		     c=`echo $expect $v | perl -anle '($e=$F[0])=~s#(\d+)#sprintf"%05d",$1#ge;($v=$F[1])=~s#(\d+)#sprintf"%05d",$1#ge;print (($e > $v) ? "red" : "green")'`; ;;
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
		if check_pm "$m" ; then text_cpan="»o-saft.tgz«"; fi
		echo_red "$text_miss $text_cpan"
		err=`expr $err + 1`
	fi
done
echo_foot

echo_head "# check for important Perl modules used by installed O-Saft"
for p in `echo $inst_directory $PATH|tr ':' ' '` ; do
	o="$p/$osaft_exe"
	[ -e "$o" ] || continue
	# NOTE: output format is slightly different, 'cause **WARNINGs are printed too
	echo "# testing $o ...$tab"
	for m in $perl_modules ; do
		echo_label "$m"
		w=`$o --no-warn +version 2>&1        | awk '/(ERROR|WARNING).*'$m'/{print}'`
		v=`$o --no-warn +version 2>/dev/null | awk '($1=="'$m'"){printf"%8s %s",$2,$3}'`
		if [ -n "$w" ]; then
			# ERROR in $w most likely means that $m is not found by
			# perl, then $v is empty
			if [ -z "$v" ]; then
				echo_red    "$w"
			else
				echo_red    "$v"
				echo_yellow "$w"
			fi
		else
			if [ -z "$v" ]; then
				echo_yellow "missing?"  # probaly due to ERROR
			else
				echo_green  "$v"
			fi
		fi
		#err=`expr $err + 1`    # already counted in previous check
	done
done
echo_foot

echo_head "# summary of warnings from installed O-Saft (should be empty)"
o="$inst_directory/$osaft_exe"
if [ -e "$o" ]; then
	echo "# testing $o in $inst_directory ...$tab"
	cd "$inst_directory"
	w=`$o +version 2>&1 | awk '/WARNING:/{print}'`
	[ -n "$w" ] && echo_yellow "$w"
fi
echo_foot

echo_head "# check for openssl executable in PATH"
echo_label "openssl" && echo_green "`which openssl`" "(`openssl version`)" \
	|| echo_yellow "missing"
# TODO: error when openssl older than 0x01000000 has no SNI
echo_foot

echo_head "# check for openssl executable used by O-Saft"
for p in `echo $inst_directory $PATH|tr ':' ' '` ; do
	o="$p/$osaft_exe"
	r="$p/.$osaft_exe"
	if [ -x "$o" ]; then
		# first call program to check if it is starting properly
		# if it fails with a status, the corresponding error is printed
		# and the extraction of the openssl executable is not done
		(
		cd "$p" # ensure that $r is used
		$o --no-warn +version >/dev/null && \
		openssl=`$o --no-warn +version 2>/dev/null | awk '/external executable/{if(3==NF){print $NF}}'` && \
		version=`$o --no-warn +version 2>/dev/null | awk '/external executable/{if(4<NF){sub(/^.*  O/,"");print}}'` && \
		echo_label "$o" && echo_green "$openssl ($version)" || echo_red "missing"
		)
	fi
done
echo_foot

echo_head "# check for optional tools to view documentation"
check_commands $tools_optional
echo_foot

echo_head "# check for contributed files (in $inst_directory/$contrib_dir )"
for c in $files_contrib $osaft_one ; do
	skip=0
	for f in $files_not_installed $files_develop ; do
		[ "$f" = "$c" ] && skip=1
	done
	[ $skip -eq 1 ] && continue
	_c=${c##*/}
	echo_label "$_c" #&& echo_green "$openssl"
	c="$inst_directory/$c"
	[ -e "$c" ] && echo_green "$c" || echo_yellow "missing $c"
	#err=`expr $err + 1`    # not counted as error
done
echo_foot

echo ""
echo -n "# checks$tab"
if [ $err -eq 0 ]; then
	echo_green "passed"
else
	echo_red   "failed , $err error(s) detected"
	[ -z "$new_dir" ] && echo "# default installation directory »$inst_directory« used;"
	[ -z "$new_dir" ] && echo "# consider using »$0 path/to/directory« "
fi

# check mode }

exit $err

