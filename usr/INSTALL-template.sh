#!/bin/sh
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
#?      with an operation mode and an installation directory. The modes are:
#?
#?          --install   - copy all necessary files into default directory
#?                        note that symbolic links cannot be copied and will
#?                        replaced by the file in the installation directory
#?                        default operation mode if no other mode given
#           --install-f - same as install, but allows execution in developer
#                         directory (not part of official help)
#?          --check     - check current installation; see  --check=*  also
#?          --clean     - move files not necessary to run O-Saft into subdir
#?                        ./.files_to_be_removed
#                This is the behaviour of the old  INSTALL-devel.sh  script.
#?          --openssl   - calls  usr/install_openssl.sh  which builds and
#?                        installs  openssl  and  Net::SSLeay ; this doesn't
#?                        support other options and arguments of
#?                        usr/install_openssl.sh
#?          --cgi       - prepare directory to be used in CGI mode
#?          --expected  - show sample output expected for  --check
#                         All lines starting with #= are the sample output.
#?          --checkdev  - check system for development (make) requirements
#?          --check=tools         - just check main tools
#?          --check=self          - just check main tool versions
#?          --check=perl          - just check Perl required modules
#?          --check=modules       - just check all required modules
#?          --check=rc            - just check resource files
#?          --check=inst          - just check installation in specified dir
#?          --check=openssl       - just check openssl       ; ;;
#?          --check=usr           - just check tools in usr/
#?          --check=podtools      - just check for tools to view POD files
#?          --check=SID           - list SIDs and md5sum of installed files
#?          --check=SID --changes - list SIDs and md5sum of changed files
#?
#?          /path/to/installation/directory
#?                      - directory used for the operation
#?                        copy all necessary files into this directory
#?                        use data in that directory for checks
#?
#?      With --install  only warnings or errors are reported. Use option --v
#?      to get a detailed report.
#=
#=# check for O-Saft programs found via environment variable PATH
#=#--------------------------------------------------------------
#=#                  wish	/usr/bin
#=#             o-saft.pl	not found in PATH, consider adding /opt/o-saft to PATH
#=#            o-saft.tcl	not found in PATH, consider adding /opt/o-saft to PATH
#=#                o-saft	not found in PATH, consider adding /opt/o-saft to PATH
#=#         o-saft-docker	not found in PATH, consider adding /opt/o-saft to PATH
#=# ./usr/o-saft-standalone.pl	.
#=#
#=# Note: all found executables in PATH are listed
#=#--------------------------------------------------------------
#=#
#=# check installation in /opt/o-saft
#=#--------------------------------------------------------------
#=# (warnings are ok if »git clone« will be used for development)
#=#       usr/.o-saft.tcl	found; file from previous installation
#=#     o-saft-docker-dev	found; file for development
#=#            Dockerfile	found; file for development
#=#              Makefile	found; file for development
#=#                    t/	found; file for development
#=#        usr/critic.sh	found; file for development
#=#               CHANGES	found; file for development
#=#                README	found; file for development
#=# consider running »INSTALL.sh --clean«
#=#--------------------------------------------------------------
#=
#=# check for used O-Saft programs (according $PATH)
#=#----------------------+---------------------------------------
#=#             o-saft.pl	24.09.24 /opt/o-saft/o-saft.pl
#=#            o-saft.tcl	    3.31 /opt/o-saft/o-saft.tcl
#=#                o-saft	     3.4 /opt/o-saft/o-saft
#=#         o-saft-docker	    3.13 /opt/o-saft/o-saft-docker
#=# usr/o-saft-standalone.pl	24.09.24 usr/o-saft-standalone.pl
#=#----------------------+---------------------------------------
#=
#=# check for installed O-Saft resource files
#=#----------------------+---------------------------------------
#=#          ./.o-saft.pl	will be used when started in . only
#=# /opt/o-saft/.o-saft.pl	will be used when started in /opt/o-saft only
#=# /home/USER/.o-saft.tcl	missing, consider generating: »o-saft.tcl --rc > /home/USER/.o-saft.tcl«
#=#----------------------+---------------------------------------
#=
#=# check for important Perl modules used by installed O-Saft
#=#----------------------+---------------------------------------
#=# testing /opt/o-saft/o-saft.pl ...	
#=#              Net::DNS	    1.29 /usr/local/share/perl/5.24.1/Net/DNS.pm
#=#           Net::SSLeay	    1.88 /usr/local/lib/x86_64-linux-gnu/perl/5.24.1/Net/SSLeay.pm
#=#      IO::Socket::INET	    1.41 /usr/local/lib/x86_64-linux-gnu/perl-base/IO/Socket/INET.pm
#=#       IO::Socket::SSL	   2.069 /usr/share/perl5/IO/Socket/SSL.pm
#=#           Time::Local	    1.28 /usr/share/perl/5.24/Time/Local.pm
#=# testing /opt/o-saft/o-saft.pl in /opt/o-saft ...	
#=#              Net::DNS	    1.29 /usr/local/share/perl/5.24.1/Net/DNS.pm
#=#           Net::SSLeay	    1.88 /usr/local/lib/x86_64-linux-gnu/perl/5.24.1/Net/SSLeay.pm
#=#       IO::Socket::SSL	   2.069 /usr/share/perl5/IO/Socket/SSL.pm
#=#           Time::Local	    1.28 /usr/share/perl/5.24/Time/Local.pm
#=#----------------------+---------------------------------------
#=
#=# check for installed Perl modules (started in »$inst_directory«)
#=#----------------------+---------------------------------------
#=#                  Carp	    1.52 /usr/lib/x86_64-linux-gnu/perl-base/Carp.pm
#=#              Net::DNS	    1.36 /usr/local/share/perl/5.24.1/Net/DNS.pm
#=#           Net::SSLeay	    1.94 /usr/local/lib/x86_64-linux-gnu/perl/5.36/Net/SSLeay.pm
#=#      IO::Socket::INET	    1.49 /usr/local/lib/x86_64-linux-gnu/perl-base/IO/Socket/INET.pm
#=#       IO::Socket::SSL	   2.081 /usr/share/perl5/IO/Socket/SSL.pm
#=#                Socket	   2.033 /usr/lib/x86_64-linux-gnu/perl-base/Socket.pm
#=#           Time::Local	    1.30 /usr/share/perl/5.24/Time/Local.pm
#=#                                      ancient module found, try installing newer version, at least  1.90
#=#                Config	5.036000 /usr/lib/x86_64-linux-gnu/perl-base/Config.pm
#=#          Math::BigInt	1.999830 /usr/share/perl/5.36/Math/BigInt.pm
#=#                  OCfg	24.09.24 lib/OCfg.pm
#=#               Ciphers	24.09.24 lib/Ciphers.pm
#=#         error_handler	24.09.24 lib/error_handler.pm
#=#               SSLinfo	24.09.24 lib/SSLinfo.pm
#=#              SSLhello	24.09.24 lib/SSLhello.pm
#=#                 OData	24.09.24 lib/OData.pm
#=#                  ODoc	24.09.24 lib/ODoc.pm
#=#                  OMan	24.09.24 lib/OMan.pm
#=#                 OText	24.09.24 lib/OText.pm
#=#                OTrace	24.09.24 lib/OTrace.pm
#=#                  OUsr	24.09.24 lib/OUsr.pm
#=#----------------------+---------------------------------------
#=
#=# summary of warnings from installed O-Saft (should be empty)
#=#----------------------+---------------------------------------
#=# testing /opt/o-saft/o-saft.pl in /opt/o-saft ...	
#=# **WARNING: 841: used openssl version '805306448' differs from compiled Net::SSLeay '805306544'; ignored
#=#----------------------+---------------------------------------
#=
#=# check for openssl executable in PATH
#=#----------------------+---------------------------------------
#=#               openssl	/usr/bin/openssl (OpenSSL 3.0.14 4 Jun 2024 (Library: OpenSSL 3.0.14 4 Jun 2024))
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
#=#               pod2pdf	/usr/bin/pod2pdf
#=#              pod2text	/usr/bin/pod2text
#=#             pod2usage	/usr/bin/pod2usage
#=#                podman	missing
#=#             podviewer	missing
#=#                  stty	/bin/stty
#=#                 tkpod	/usr/bin/tkpod
#=#                  tput	/usr/bin/tput
#=#
#=# Note: podman is a tool to view pod files, or it's a container engine
#=#----------------------+---------------------------------------
#=
#=# check for contributed files (in »/opt/o-saft/usr«)
#=#----------------------+---------------------------------------
#=#     Cert-beautify.awk	/opt/o-saft/usr/Cert-beautify.awk
#=#      Cert-beautify.pl	/opt/o-saft/usr/Cert-beautify.pl
#=#       HTML-simple.awk	/opt/o-saft/usr/HTML-simple.awk
#=#        HTML-table.awk	/opt/o-saft/usr/HTML-table.awk
#=#       HTML4-table.awk	/opt/o-saft/usr/HTML4-table.awk
#=#       HTML5-table.awk	/opt/o-saft/usr/HTML5-table.awk
#=#        JSON-array.awk	/opt/o-saft/usr/JSON-array.awk
#=#       JSON-struct.awk	/opt/o-saft/usr/JSON-struct.awk
#=#     XML-attribute.awk	/opt/o-saft/usr/XML-attribute.awk
#=#         XML-value.awk	/opt/o-saft/usr/XML-value.awk
#=#       alertscript.cfg	/opt/o-saft/usr/alertscript.cfg
#=#        alertscript.pl	/opt/o-saft/usr/alertscript.pl
#=# bash_completion_o-saft	/opt/o-saft/usr/bash_completion_o-saft
#=#               bunt.pl	/opt/o-saft/usr/bunt.pl
#=#               bunt.sh	/opt/o-saft/usr/bunt.sh
#=#    checkAllCiphers.pl	/opt/o-saft/usr/checkAllCiphers.pl
#=#       cipher_check.sh	/opt/o-saft/usr/cipher_check.sh
#=# dash_completion_o-saft	/opt/o-saft/usr/dash_completion_o-saft
#=#       filter_examples	/opt/o-saft/usr/filter_examples
#=# fish_completion_o-saft	/opt/o-saft/usr/fish_completion_o-saft
#=#       lazy_checks.awk	/opt/o-saft/usr/lazy_checks.awk
#=#             symbol.pl	/opt/o-saft/usr/symbol.pl
#=# tcsh_completion_o-saft	/opt/o-saft/usr/tcsh_completion_o-saft
#=#        usage_examples	/opt/o-saft/usr/usage_examples
#=#         zap_config.sh	/opt/o-saft/usr/zap_config.sh
#=#        zap_config.xml	/opt/o-saft/usr/zap_config.xml
#=#  o-saft-standalone.pl	/opt/o-saft/usr/o-saft-standalone.pl
#=#----------------------+---------------------------------------
#=
#=# checks	passed
#=# default installation directory »/opt/o-saft« used
#=
#=#-------------------+--------------------- not part of output {
#=# Note: above examples are from 2018, more modern (2025) versions are:
#=#               openssl	  3.0.11
#=#                  Perl	    5.38
#=#         Tcl/Tk (wish)	  8.6.13/8.6.13
#=#              Net::DNS	    1.36
#=#           Net::SSLeay	    1.94
#=#                Socket	   2.033
#=#            IO::Socket	    1.49
#=#       IO::Socket::SSL	   2.081
#=#           Time::Local	    1.30
#=#-------------------+--------------------- not part of output }
#?
#? OPTIONS
#?      --h     - got it
#       --help  - got it
#?      --help update
#?      --help=update   - just print description about CHECKS and UPDATES
#?      --n     - do not execute, just show (ignored for  --check)
#?      --i     - ignore error while installing; default: exit with status 4
#?      --v     - print verbose information about performed actions
#?      -x      - debug using shell's "set -x"
#?      --check --checkdev --clean --cgi --expected --install --openssl
#?                      - these are commands, see  DESCRIPTION  above
#?      --force         - install  RC-FILEs  .o-saft.pl  and  .o-saft.tcl in
#?                        $HOME, overwrites existing ones
#?      --instdev       - copy also all files necessary for development into
#?                        specified directory; implies --install
#?      --changes       - report only changes with --check=SID
#?      --no-colour     - do not use coloured texts; default
#?      --colour        - use coloured texts (red, yellow, blue|green)
#?      --colour-blind  - same as --colour
#?      --colour-not-blind  - use green instead of blue coloured texts
#?      --other         - check for other SSL-related tool with  --checkdev
#?      --useenv        - change #! (shebang) lines to  #!/usr/bin/env
#?                        Involves  --install .
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
#?                        Involves  --install --useenv .
#?                        Applies the change to shebang lines with arguments.
#?      --noargs        - remove arguments from #! (shebang) lines
#?                        Option is ignored when  --useenv  or  --gnuenv  is
#?                        also used. Applies to  .pl  and  .pm  files only.
#                         Useful to remove for example -CADSio  which causes
#                         Perl to exit when used like:  perl o-saft.pl ...
#?
#?      Warning about wrong checksum like
#?          **WARNING: wrong checksum ...
#?      may be harmless and occur when:
#?          - using options  --useenv or --gnuenv or --noargs
#?          - files are cloned or pulled from repository
#?
#?      Please see  doc/concepts.txt  for details about /usr/bin/env .
#?      It's up to the user then, which solution fits better.
#?
#? ENVIRONMENT
#?      Environment variable  OSAFT_DIR is used for the default installation
#?      directory.
#?          env OSAFT_DIR=/some/dir $0 --install
#?          env OSAFT_DIR=. $0 --check
#?
#? CHECKS, UPDATES
#?   Abstract
#?      This script can be used to check or update the current installation.
#?      Checking or updating the installation works best if the installation
#?      is just the directory provided by the tarball (o-saft.tgz usually).
#?      This directory is  O-Saft  (/O-Saft in a container).  For simplicity
#?      following examples mainly use  .  for that directory.
#?
#?   Checksum
#?      Checksums (more precise cryptographic hashes) are used for the files
#?      of the tool and the tarball used for installation.
#?
# critical files
#      o-saft.tgz    - https://github.com/OWASP/O-Saft/raw/master/o-saft.tgz
#      +its checksum - https://raw.githubusercontent.com/OWASP/O-Saft/master/o-saft.tgz.sha256
#                      also mentioned in: Dockerfile, README.md
#      o-saft.rel    - part of o-saft.tgz, hence verified by that
#                      https://github.com/OWASP/O-Saft/blob/master/doc/o-saft.rel
#                      will only be updated there when new version at github is released
#?      TBD ...
#?
#?   Checks
#?      For checks please refer to the operation modes --check*  above.
#?
#?   Check examples
#?      # check SIDs and checksums of all installed files:
#?          $0 . --check=SID --changes
#?      - should return an empty list like:
#?          # ./INSTALL.sh 3.75; --check=SID  . ...
#?
#?          # SID   date    time    md5sum   filename    path
#?          #----------------------+--------+-------------------------------
#?          #----------------------+--------+-------------------------------
#?
#?      - lines are listed these files have been modified after installtion.
#?
#?      # check SIDs and checksums of a single files:
#?          usr/get-SIDs.sh --check .o-saft.pl
#?      - should return something like:
#?          # 1.115 24/09/06 23:42:42 771cf961dc1004d88f24011945c5d021 .o-saft.pl .o-saft.pl
#?          # 1.115 24/09/06 23:42:42 771cf961dc1004d88f24011945c5d021 .o-saft.pl .o-saft.pl
#?      - the md5sum in both lines must be identical, otherwise the file has
#?        been modified after installtion.
#?
#?   Updates
#      When updating files from github (or other sources), any check of SID
#      or checksum should report differences, at least the checksum.
#
#      Updating from a tarball from github should not report checksum diffs.
#?
#?      TBD ...
#?
#?   Update examples
#?      TBD ...
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
#?      $0 /opt/bin/ --noargs
#?      $0 --install /opt/bin/
#?      $0 --install /tmp/dir/ --instdev
#?      $0 --check   /opt/bin/
#?      $0 --check   /opt/bin/ --colour
#?      $0 --checkdev
#?      $0 --cgi /opt/bin/
#?      $0 --cgi .
#?
#? SEE ALSO
#?      usr/install_openssl.sh
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
#       Silently accepts the options  -n  or  -h  or  --x  also.
#       Silently accepts the options  --usage  to simulate empty arguments.
#
#    echo vs /bin/echo
#       echo is a pain, depending on the platform. The shell's built-in echo
#       does not have the  -n  option, usually. /bin/echo doesn't know about
#       ANSI escape sequences, usually. \-escaped characters, like  \t , are
#       another problem, some shells support them, others do not.
#       I.g. we'd like to use traditional bourne shell, where all behaviours
#       are well defined. Unfortunately, some platforms seem to be a hostage
#       of their developers who believe that  their favorite shell has to be
#       used by all users (for example by using a symbolic link for  /bin/sh
#       to whatever, without informing the user).
#       Best effort to get this script working on most platforms was:
#           * mainly use /bin/echo (aliased to echo, to keep code readable)
#           * TABs (aka \t aka 0x09) are used verbatim (see $t variable)
#           * shell's built-in echo used when ANSI escape sequences are used
#       There's no guarantee that it works flawless on everywhere, currently
#       (8/2019) it works for BSD, debian (including Mac OSX).
#       Functionality of this script is not harmed,  if the output with echo
#       fails (prints ANSI escapes and/or \-escapes verbatim,  and/or prints
#       -n verbatim, etc.).
#
#    INSTALL.sh.lock
#       If the file  INSTALL.sh.lock exists in the source or destination dir
#       mv and rm commands will not be executed (--cgi, --clean --install).
#       This is not officially described with  --help  because it is used to
#       to protect the develepopment directory for unintended use.
#       
#
#? DEPENDENCIES
#?      Following tools are required for proper functionality:
#?          awk, cat, perl, sed, tr, /bin/echo
#?
#? VERSION
# added with --help
#?
#? AUTHOR
#?      16. September 2016 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

#_____________________________________________________________________________
#_____________________________________________ internal variables; defaults __|
SID="@(#) INSTALL-template.sh 3.75 25/04/09 11:56:26"
try=''
ich=${0##*/}
dir=${0%/*}
[ "$dir" = "$0" ] && dir="." # $0 found via $PATH in .
# note that all variables are used global
lock="INSTALL.sh.lock"
src_directory="$dir"
clean_directory=".files_to_be_removed"  # must be set after reading arguments
_break=                 # --break  if screen width < 50; then use two lines as output
colour=""               # 32 green, 34 blue for colour-blind
noargs=                 # --noargs use plain shebang lines without options
useenv=                 # --useenv to change shebang lines to /usr/bin/env
gnuenv=                 # --gnuenv to change shebang lines to /usr/bin/env -S
ignore=                 # --ignore ignore errors, continue script instead of exit
other= 
force= 
instdev=                # 1 install development files also
changes=                # 1 show only changed file with --check=SID
optn=""
optv=                   # 1 print verbose information
mode=""                 # "", cgi, check, clean-up, install, openssl
alias echo=/bin/echo    # need special echo which has -n option;
	                # TODO: check path for each platform
tab="	"               # need a real TAB (0x09) for /bin/echo

unset OSAFT_OPTIONS     # may be set by make, distorts some strings here

text_miss="missing, try installing from/with";
text_old="ancient module found, try installing newer version, at least "
text_one="missing, consider generating with »make standalone«"
text_path="Note: all found executables in PATH are listed"
text_prof="Note: Devel::DProf Devel::NYTProf and GraphViz2 may wrongly be missing"
text_podm="Note: podman is a tool to view pod files, or it's a container engine"
text_dev="file for development"
text_alt="from previous installation"

# INSERTED_BY_MAKE {
osaft_sh="INSERTED_BY_MAKE_OSAFT_SH"
osaft_pm="INSERTED_BY_MAKE_OSAFT_PM"
osaft_exe="INSERTED_BY_MAKE_OSAFT_PL"
osaft_cgi="INSERTED_BY_MAKE_OSAFT_CGI"
osaft_gui="INSERTED_BY_MAKE_OSAFT_GUI"
osaft_rel="INSERTED_BY_MAKE_OSAFT_REL"
osaft_one="INSERTED_BY_MAKE_OSAFT_STAND"
osaft_sid="INSERTED_BY_MAKE_OSAFT_GETSID"
osaft_dock="INSERTED_BY_MAKE_OSAFT_DOCKER"
doc_dir="INSERTED_BY_MAKE_DOC_DIR"
lib_dir="INSERTED_BY_MAKE_LIB_DIR"
usr_dir="INSERTED_BY_MAKE_USR_DIR"
tst_dir="INSERTED_BY_MAKE_TST_DIR"
log_dir="INSERTED_BY_MAKE_LOG_DIR"
inst_directory=${OSAFT_DIR:="INSERTED_BY_MAKE_INSTALLDIR"} # use environment varaibale OSAFT_DIR if set
perl_modules="INSERTED_BY_MAKE_PERL_MODULES"
osaft_subdirs="INSERTED_BY_MAKE_OSAFT_DIRS"
osaft_libdir="INSERTED_BY_MAKE_OSAFT_LIBDIR"

osaft_modules="
	INSERTED_BY_MAKE_OSAFT_MODULES
"

file_cgi_html="INSERTED_BY_MAKE_OSAFT_CGI_HTML"
files_contrib="
	INSERTED_BY_MAKE_CONTRIB
"

files_install="
	INSERTED_BY_MAKE_OSAFT
"

files_install_cgi="
	INSERTED_BY_MAKE_OSAFT_INSTCGI
"

files_install_doc="
	INSERTED_BY_MAKE_OSAFT_DOC
"

files_install_dev="
	INSERTED_BY_MAKE_DEV_FILES
"

files_all_src="
	INSERTED_BY_MAKE_ALL_SRC
"

files_develop="
	INSERTED_BY_MAKE_DEV_OTHER
"

files_info="
	INSERTED_BY_MAKE_DEV_INFO
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

dirs__ancient="contrib Net OSaft/Doc OSaft"
files_ancient="
	generate_ciphers_hash openssl_h-to-perl_hash o-saft-README
	o-saft-dbx.pm o-saft-lib.pm o-saft-man.pm o-saft-usr.pm osaft.pm
	checkAllCiphers.pl INSTALL-devel.sh .perlcriticrc o-saft_bench
	contrib/.o-saft.tcl contrib/o-saft.cgi
"

# first, dirty hack to make tests in development mode possible
# remember the inserted "" to avoid substitutions here
[ "INSERTED_""BY_MAKE_OSAFT_SH"   = "$osaft_sh"     ] && osaft_sh=o-saft
[ "INSERTED_""BY_MAKE_OSAFT_PL"   = "$osaft_exe"    ] && osaft_exe=o-saft.pl
[ "INSERTED_""BY_MAKE_OSAFT_CGI"  = "$osaft_cgi"    ] && osaft_gui=o-saft.cgi
[ "INSERTED_""BY_MAKE_OSAFT_GUI"  = "$osaft_gui"    ] && osaft_gui=o-saft.tcl
[ "INSERTED_""BY_MAKE_OSAFT_DOCKER" = "$osaft_dock" ] && osaft_dock=o-saft-docker
[ "INSERTED_""BY_MAKE_OSAFT_rel"  = "$osaft_rel"    ] && osaft_rel=doc/o-saft.rel
[ "INSERTED_""BY_MAKE_USR_DIR"    = "$usr_dir"      ] && usr_dir=usr

# some files "not to be installed" are ancient, they are kept here in
# $files_not_installed to ensure that outdated content is also handled
# the generated "graph" files are also hardcoded here
files_not_installed="
	$usr_dir/o-saft.cgi  $usr_dir/o-saft.php  $usr_dir/Dockerfile*
	$usr_dir/distribution_install.sh   $usr_dir/gen_standalone.sh
	$usr_dir/install_perl_modules.pl   $usr_dir/install_openssl.sh
	$usr_dir/INSTALL-template.sh
	$doc_dir/*graph-annotations.*      $doc_dir/*graph-sub-call*
"

# HARDCODED }

osaft_exerc=".$osaft_exe"
osaft_guirc=".$osaft_gui"
build_openssl="$usr_dir/install_openssl.sh"
all_exe="$osaft_exe $osaft_gui $osaft_sh $osaft_dock $osaft_one"
    # checking INSTALL.sh (myself) is pointless, somehow ...

_line='----------------------+--------+--------'
_cols=0
\command -v \tput >/dev/null && _cols=$(tput cols 2>/dev/null || echo "0")
    # if $TERM is not set, tput would complain with:
    #    tput: No value for $TERM and no -T specified
    # hence redirected to /dev/null
if [ 0 -lt $_cols ]; then
	# adapt _line to screen width
	[ -n "$OSAFT_MAKE" ] && _cols=78           # SEE Make:OSAFT_MAKE
	[ 51 -gt $_cols ]    && _break="--break"   # see echo_label()
	while [ 42 -lt $_cols ]; do
		# FIXME: some terminal break line when colour is used
		_line="$_line-"
		_cols=`expr $_cols - 1`
	done
fi

#_____________________________________________________________________________
#________________________________________________________ general functions __|
__exit      () {
	[ -n "$ignore" ] && return
	exit $@
}
echo_grey   () {
	[ -z "$colour" ] && echo "$@" && return
	\echo "\033[7;33m\033[1;30m$@\033[0m"
}
echo_info   () {
	[ -z "$optv" ] && return
	if [ -z "$colour" ]; then
		\echo "# $@"
	else
		echo_grey "# $@"
	fi
}
echo_head   () {
	echo ""
	if [ -z "$colour" ]; then
		\echo "$@"
		\echo "#$_line"
	else
		#echo_grey "$@"
		#echo_grey "#$_line"
		\echo "\033[7;37m\033[1;30m$@"
		\echo "#$_line\033[0m"
	fi
}
echo_foot   () {
	if [ -z "$colour" ]; then
		echo "#$_line"
	else
		echo_grey "#$_line"
	fi
}
echo_label  () {
	\perl -le "printf'# %21s%c','$@',0x09"  # use perl instead of echo for formatting
	[ -z "$_break" ] && return
	\perl -le 'printf"\n\t"'                # use additional line
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
echo_error  () {
	# $1 number of errors
	echo ""
	echo -n "# checks$tab"
	if [ $1 -eq 0 ]; then
		echo_green "passed"
	else
		echo_red   "failed , $1 error(s) detected"
	fi
	return
}
_help       () {
	# $1 is start of scope to be printed, if equal NAME then print all
	anf=$1
	end='^#? *[A-Z][A-Z]'
	shift
	[ "$anf" = "NAME" ] && end='^ *$'
	\sed -n -e "/^#? *${anf}/,/${end}/p" $0 | \
	\sed -n -e "s/\$0/$ich/g" \
		-e '/^#?/s/#?//p' \
		-e "/VERSION$/a\      $SID"
	exit 0
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

check_commands  () {
	for c in $* ; do
		echo_info "check prog $c .."
		echo_label "$c"
		is=$(\command -v $c)
		[ -n "$is" ] && echo_green "$is" || echo_red "missing"
	done
	return
} # check_commands

check_development () {
	# $1 is -d -e -f or -L ; $2 is name of directory, file, link, ...
	# use own label instead of echo_label
	\perl -le "printf'# %25s%c','$2',0x09"
	if [ $1 "$2" ]; then
		echo_green  "OK"
	else 
		echo_red "missing; install with: »$0 $inst_directory --instdev«"
		err=`expr $err + 1`
	fi
	return
} # check_development

check_exec  () {
# TODO: this is a variant of check_development(), should be implemented there
	for c in $* ; do
		echo_info "check exec $c .."
		echo_label "$c"
		[ -x "$c" ] && echo_green "OK" || echo_red "not executable"
		[ -x "$c" ] || err=`expr $err + 1`
	done
	return
} # check_exec

copy_file   () {
	src=$1
	dst=$2
	convert=0
	ext=${src##*.}
	file=${src##*/}
	if [ -n "$useenv" ]; then
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
	if [ -n "$noargs" ]; then
		case "$ext" in
		    pl | pm)  convert=2 ; ;;
		esac
	fi
	#dbx# \perl -lane 'if(1==$.){exit 1 if m|^#\!\s*/usr/bin/env |}' "$src" || echo skip $src ...
	\perl -lane 'if(1==$.){exit 1 if m|^#\!\s*/usr/bin/env |}' "$src" || convert=0
	case "$convert" in
	  0)    # just copy
		echo_info "  cp    $src $dst"
		$try \cp --preserve=all "$src"  "$dst"  || __exit 4
		;;
	  1)    # --gnuenv or --useemv
		echo_info "install converted $src ..."
		# only the very first line $. ist changed
		if [ -n "$try" ]; then
		    echo 'perl -lane "if(1==$.){s|^.*?/([a-zA-Z0-9_.-]+$)|#\!/usr/bin/env $1|;}print;" '"'$src' > '$dst'"
		    return
		fi
		# convert only  "#! /some/path/tool"
		\perl -lane 'if(1==$.){s|^.*?/([a-zA-Z0-9_.-]+)\s*$|#\!/usr/bin/env $1|;}print;' \
			"$src" > "$dst"  || __exit 4
		if [ -n "$gnuenv" ]; then
		# convert only  "#! /some/path/tool arg..."
		\perl -lane 'if(1==$.){exit 1 if m|^#.*?/([a-zA-Z0-9_.-]+)\s(.*)$|;}' "$src" || \
		\perl -lane 'if(1==$.){s|^#.*?/([a-zA-Z0-9_.-]+)\s(.*)$|#\!/usr/bin/env -S $1 $2|;}print;' \
			"$src" > "$dst"  || __exit 4
		fi
		# set proper modes
		\chmod 555 "$dst" # assuming that it is and should be executable
		;;
	  2)    # --noargs
		# only the very first line $. ist changed
		# lines may look like:
			#!/usr/bin/perl -CADSio
			#! /usr/bin/perl -w -I .
			#! /bin/perl
		# note that following match does not need to contain /perl,
		# it's assumed, that the check for $ext above selects proper
		# files only
		# TODO: rarely used "#!/usr/bin/env -S .." will be changed also
		if [ -n "$try" ]; then
		    echo 'perl -lane "if(1==$.){s|^([#/!a-zA-Z0-9_.-]+).*|$1|;}print;" '"'$src' > '$dst'"
		    return
		fi
		\perl -lane 'if(1==$.){s|^([#/!a-zA-Z0-9_.-]+).*|$1|;}print;' \
			"$src" > "$dst"  || __exit 4
		# convert only  "#! /some/path/tool"
		\chmod 555 "$dst"
		;;
	esac # $convert
	return
} # copy_file

check_md5   () {
	# compute md5sum and compare with value in *.rel file; increments $err
	# TODO: md5sum useless for converted files, as it differs always
	_rel=$1
	_dst=$2
	[ -e "$_dst" ] || echo_yellow "**WARNING: missing »$_dst«; checksum ignored"
	[ -e "$_dst" ] || return
	name=${_dst##*/}   # filename without path because / causes problem in awk
	[ ! -e "$_rel" ] && return  # warning already printed
	# get expected md5sum
		# ^[0-9]       - to ensure matching lines with SID
		#         SID %I (edited file) does not match and will be reported
		# (^|.*\/)     - to ensure matching path or bare name
		# exit         - to ensure only one (first) value is returned
	md5sum=`\awk '/^[0-9]/{if($6~/(^|.*\/)'$name'$/){print $4;exit}}' $_rel`
	newsum=`\md5sum $_dst` # compute m5sum of installed file
	newsum=${newsum%% *}   # remove trailing filename
	#dbx# echo "# $name : $md5sum : $newsum."
	[ "$md5sum" = "$newsum" ] || echo_yellow "**WARNING: wrong checksum $newsum for »$_dst«"
	[ "$md5sum" = "$newsum" ] || err=`expr $err + 1`
	return
} # check_md5

#_____________________________________________________________________________
#__________________________________________________________ check functions __|
check_tools () {
	[ "check" = "$mode" ] || echo_info "check_tools() ..."
	echo_head "# check for O-Saft programs found via environment variable PATH"
	echo_info "PATH$tab$PATH"
	_cnt=0
	_gui=0
	for p in `echo $PATH|\tr ':' ' '` ; do
		for o in $all_exe perl wish ; do
			exe="$p/$o"
			echo_info "check $p/$o .."
			if [ -e "$exe" ]; then
				_cnt=`expr $_cnt + 1`
				echo_label "$exe" && echo_green "$p"
				#echo_label "$exe" && echo_yellow "missing"
			fi
			[ "$o" != "wish" ] && continue
			if [ -e "$exe" ]; then
				_gui=`expr $_gui + 1`
				echo_label "wish" && echo_green "$p"
			fi
		done
	done
	echo "#"
	echo "# $text_path"
	[ 0 -eq $_cnt   -o   0 -eq $_gui ] && echo "#"
	[ 0 -eq $_cnt ] && echo_label  "$osaft_exe" \
			&& echo_yellow "not found in PATH, consider adding $inst_directory to PATH"
	[ 0 -eq $_gui ] && echo_label  "wish" \
			&& echo_yellow "not found in PATH, consider installing wish" \
			&& osaft_gui=
	[ -e "$osaft_one" ] || ( echo_label "$osaft_one" && echo_yellow "$text_one" )
	echo_foot
	return
} # check_tools

check_inst  () {
	[ "check" = "$mode" ] || echo_info "check_inst() ..."
	echo_head "# check installation in $inst_directory"
	echo      "# (warnings are ok if »git clone« will be used for development)"
	_cnt=0
	# err=`expr $err + 1` ; # errors not counted here
	for f in $dirs__ancient ; do
		echo_info "check $f .."
		[ -d "$f" ] && echo_label  "$f" \
			    && echo_yellow "found; directory $text_alt" \
			    && _cnt=`expr $_cnt + 1`
	done
	for f in $files_ancient ; do
		echo_info "check $f .."
		[ -e "$f" ] && echo_label  "$f" \
			    && echo_yellow "found; file $text_alt" \
			    && _cnt=`expr $_cnt + 1`
	done
	for f in $files_develop $files_info ; do
		echo_info "check $f .."
		[ -e "$f" ] && echo_label  "$f" \
			    && echo_yellow "found; $text_dev" \
			    && _cnt=`expr $_cnt + 1`
	done
	[ 0 -ne $_cnt ] && echo -n "# " \
			&& echo_yellow "consider running »$0 --clean $inst_directory« "
	echo_foot
	return
} # check_inst

check_self  () {
	[ "check" = "$mode" ] || echo_info "check_self() ..."
	echo_head '# check for used O-Saft programs (according $PATH)'
	for o in $all_exe ; do
		# $osaft_cgi cannot be checked here because it behaves different
		_opt="+VERSION"
		echo_info "check self $o .."
		[ "o-saft-docker" = $o ] && _opt="+V" # has no own +VERSION, see source there
		if [ "o-saft.tcl" = $o ]; then
			[ -z "$osaft_gui" ] && \
				echo_yellow "not checked because »wish« missing" && \
				continue
		fi
		echo_label "$o"
		e=$(\command -v $o)
		if [ -n "$e" ] ; then
			_b='`'  # using backticks in echo is tricky ...
			[ -n "$try" ] && echo "$_b$o $_opt$_b" && continue
			v=`$o $_opt`
			_txt=`echo "$v $e"|\awk '{printf("%8s %s",$1,$2)}'`
			echo_green "$_txt"
		else
			err=`expr $err + 1`
			echo_red   "not found"
		fi
	done
	echo_foot
	return
} # check_self

check_rc    () {
	[ "check" = "$mode" ] || echo_info "check_rc() ..."
	echo_head "# check for installed O-Saft resource files"
	# currently no version check
	_cnt=0
	for p in `echo $HOME $PATH|\tr ':' ' '` ; do
		_rc="$p/$osaft_exerc"
		echo_info "check rc  $_rc .."
		if [ -e "$_rc" ]; then
			_cnt=`expr $err + 1`
			echo_label "$_rc" && echo_yellow "will be used when started in »$p« only"
		fi
	done
	[ 0 -eq $_cnt ] && echo_yellow "$rc not found"
	_rc="$HOME/$osaft_guirc"
	echo_info "check rc  $_rc .."
	if [ -e "$_rc" ]; then
		v=`\awk '/RCSID/{print $3}' $_rc|\tr -d '{};'`
		echo_label "$_rc" && echo_green  "$v"
		_txt="ancient"
	else
		_txt="missing"
	fi
	echo_label "$_rc" && echo_yellow "$_txt, consider generating: »$osaft_gui --rc > $_rc«"
	echo_foot
	return
} # check_rc

check_usr   () {
	[ "check" = "$mode" ] || echo_info "check_usr() ..."
	echo_head "# check for contributed files (in »$inst_directory/$usr_dir«)"
	for c in $files_contrib $osaft_one ; do
		_skip=0
		for f in $files_not_installed $files_develop ; do
			[ "$f" = "$c" ] && _skip=1
		done
		[ $_skip -eq 1 ] && continue
		echo_info "check $c .."
		_c=${c##*/}
		echo_label "$_c" #&& echo_green "$openssl"
		c="$inst_directory/$c"
		[ -e "$c" ] && echo_green "$c" || echo_yellow "missing $c"
		#err=`expr $err + 1`    # not counted as error
	done
	echo_foot
	return
} # check_usr

check_perl  () {
	[ "check" = "$mode" ] || echo_info "check_perl() ..."
	echo_head "# check for important Perl modules used by installed O-Saft"
	for p in `echo $inst_directory $PATH|\tr ':' ' '` ; do
		o="$p/$osaft_exe"
		[ -e "$o" ] || continue
		# NOTE: output format is slightly different, 'cause **WARNINGs are printed too
		echo "# testing $o ...$tab"
		for m in $perl_modules ; do
			echo_info "check $m .."
			echo_label "$m"
			[ -n "$try" ] && echo "$_b$o --no-warn +version 2>&1 | perl '... m/$m/ ...$_b" && continue
			w=`$o --no-warn +version 2>&1        | \awk '/(ERROR|WARNING).*'$m'/{print}'`
			v=`$o --no-warn +version 2>/dev/null | \perl -alne 'printf("%8s %s",$F[1],join(" ",@F[2..@F-1])) if $F[0] eq "'$m'"'`
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
	return
} # check_perl

check_modules   () {
	[ "check" = "$mode" ] || echo_info "check_modules() ..."
	echo_head "# check for installed Perl modules (started in »$inst_directory« )"
	for m in $perl_modules $osaft_modules ; do
		echo_info "check $m .."
		echo_label "$m"
		text_cpan="»cpan $m«"
		v=`\perl -I $osaft_libdir -M$m -le 'printf"%8s",$'$m'::VERSION' 2>/dev/null`
		p=`\perl -I $osaft_libdir -M$m -le 'my $idx='$m';$idx=~s#::#/#g;printf"%s",$INC{"${idx}.pm"}' 2>/dev/null`
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
					c=`echo $expect $v | \perl -lane '($e=$F[0])=~s#(\d+)#sprintf"%05d",$1#ge;($v=$F[1])=~s#(\d+)#sprintf"%05d",$1#ge;print (($e > $v) ? "red" : "green")'`; 
				fi
				;;
		  	*) # our own modules
			[ -n "$try" ] && echo "${_b}echo $expect | perl -lane '... (> $v) ...$_b" && continue
		     	c=`echo $expect $v | \perl -lane '($e=$F[0])=~s#(\d+)#sprintf"%05d",$1#ge;($v=$F[1])=~s#(\d+)#sprintf"%05d",$1#ge;print (($e > $v) ? "red" : "green")'`; ;;
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
	return
} # check_modules

check_summary   () {
	[ "check" = "$mode" ] || echo_info "check_summary() ..."
	echo_head "# summary of warnings from installed O-Saft (should be empty)"
	o="$inst_directory/$osaft_exe"
	if [ -e "$o" ]; then
		echo "# testing $o in $inst_directory ...$tab"
		cd "$inst_directory"
		w=`$o +version --warning-ignore=150 2>&1 | \awk '/WARNING:/{print}'`
		[ -n "$w" ] && echo_yellow "$w"
			# --warning-ignore=150 is contribution to openssl 3.x
	fi
	echo_foot
	return
} # check_summary

check_openssl   () {
	[ "check" = "$mode" ] || echo_info "check_openssl() ..."
	echo_head "# check for openssl executable in PATH"
	echo_label "openssl" && echo_green "$(\command -v openssl) (`openssl version`)" \
		|| echo_yellow "missing"
	# TODO: error when openssl older than 0x01000000 has no SNI
	echo_foot
	#
	echo_head "# check for openssl executable used by O-Saft"
	for p in `echo $PATH|\tr ':' ' '` ; do
		echo_info "check $p .."
		o="$p/$osaft_exe"
		r="$p/.$osaft_exe"
		if [ -x "$o" ]; then
			_pwd=`\pwd`
			if [ "t" = `basename $_pwd` -a ".." = "$p" ]; then
				# contribution to our make
				o="${_pwd%/*}/$osaft_exe"  # full path
				echo_yellow "**WARNING: call in development directory t/.. assumed; using »$o«"
			fi
			[ -n "$try" ] && echo "$_b$o --no-warn +version 2>&1 | awk '/external executable/{print \$NF}'$_b" && continue
			# first call program to check if it is starting properly
			# if it fails with a status, the corresponding error is printed
			# and the extraction of the openssl executable is not done
			(
			cd "$p" # ensure that $r is used
			$o --no-warn +version >/dev/null && \
			openssl=`$o --no-warn +version 2>/dev/null | \awk '/external executable/{if(3==NF){print $NF}}'` && \
			version=`$o --no-warn +version 2>/dev/null | \awk '/external executable/{if(4<NF){sub(/^.*  O/,"O");print}}'` && \
			echo_label "$o" && echo_green "$openssl ($version)" || echo_red "missing"
			)
		fi
	done
	echo_foot
	return
} # check_openssl

check_podtools  () {
	[ "check" = "$mode" ] || echo_info "check_podtools() ..."
	echo_head "# check for optional tools to view documentation"
	check_commands $tools_optional
	echo      "#"
	echo      "# $text_podm"
	echo_foot
	return
} # check_podtools

check_sids  () {
	[ "check" = "$mode" ] || echo_info "check_sids() ..."
	#echo_head "# check SIDs of installed files"
	echo_head "# SID	date	time	md5sum	filename	path"
		# must use literal TAB instead of \t (problem in BusyBox)
	if [ -n "$changes" ]; then
		# show diff only (tested with GNU diff only)
		\echo "$files_all_src" | $osaft_sid | \diff $osaft_rel -
	else
		\echo "$files_all_src" | $osaft_sid
	fi
	echo_foot
	echo_grey "# some files in doc/ t/ and usr/ don't have a SID"
	return
} # check_sids

mode_check  () {
	echo_info "mode_check() ..."
	echo_info "PATH$tab$PATH"
	check_tools
	check_inst
	check_self
	check_rc
	# from here on, all **WARNINGS (from $osaft_exe) are not important
	# and hence redirected to /dev/null
	check_perl
	check_modules
	check_summary
	check_openssl
	check_podtools
	check_usr

	echo_error $err

	# more hints, if no installation directory was given
	[ -z "$new_dir" ] && echo "# default installation directory »$inst_directory« used"
	[ -z "$new_dir" ] && echo "# consider using »$0 path/to/directory« "
    	# last message also occurs if OSAFT_DIR was used; that's OK
	return
} # mode_check

mode_checkdev () {
	echo "# mode_checkdev() ..."
	# does not use echo_info(), because text always printed
	echo      "# check system for development usage ..."
	echo_head "# check setup for development ..."
	for f in $files_info $files_develop; do
		echo_info "check file $f .."
		d="$inst_directory/$f"
		check_development -f $d
	done
	d="$inst_directory/$tst_dir"
	check_development -d $d
	for d in $doc_dir $lib_dir $usr_dir; do
		d="$inst_directory/$tst_dir/$d"
		echo_info "check link $d .."
		check_development -L $d
	done
	for f in $files_install_dev; do
		d="$inst_directory/$f"  # $f already contains $tst_dir
		echo_info "check file $f .."
		check_development -f $d
	done
	echo_head "# check for own tools used with/in make targets"
	check_commands $tools_intern
	echo_head "# check for standard tools used with/in make targets"
	check_commands $tools_extern
	echo_head "# check if own Perl modules are executable"
	check_exec $osaft_pm
	echo_head "# check if own tools are executable"
	check_exec $tools_intern
	echo      "#"
	echo      "# $text_podm"
	echo_foot
	echo_head "# check for Perl modules used with/in make targets"
	for m in $tools_modules ; do
		echo_label "$m"
		# NOTE: -I . used to ensure that local ./Net is found
		v=`\perl -I . -M$m -le 'printf"%8s",$'$m'::VERSION' 2>/dev/null`
		if [ -n "$v" ]; then
			echo_green  "$v"
		else 
			echo_red "missing; install with: »cpan $m«"
			err=`expr $err + 1`
		fi
	done
	echo      "#"
	echo      "# $text_prof"
	echo_foot
	echo ""
	if [ -n "$other" ]; then
		# printed with --other only
		echo_head "# check for other SSL-related tools"
		check_commands $tools_other
		echo_foot
	fi
	echo_error $err
	return
} # mode_checkdev

mode_install () {
	echo_info "mode_install() ..."
	echo_info "$mode from $src_directory"
	echo_info "force=$force , ignore=$ignore , instdev=$instdev , gnuenv=$gnuenv , useenv=$useenv , noargs=$noargs"
	err=0
	if [ ! -d "$inst_directory" ]; then
		echo_red "**ERROR: 040: $inst_directory does not exist; exit"
		[ -n "$try" ] || exit 2
		# with --n continue, so we see what would be done
	fi
	if [ ! -e "$src_directory/$osaft_rel" ]; then
		echo_yellow "**WARNING: missing »$src_directory/$osaft_rel«; checksum ignored"
	fi

	files="$files_install $files_install_cgi $files_install_doc $files_contrib $osaft_one"

	echo_info "searching for files newer than $src_directory/$osaft_rel ..."
	ts_rel=$(command ls -l --time-style=+%s $src_directory/$osaft_rel |awk '{print $6}')
	newer=
	for f in $files ; do
		ts_src=$(command ls -l --time-style=+%s $src_directory/$f |awk '{print $6}')
		#dbx# echo "TS $ts_rel -lt $ts_src $f"
		[ $ts_rel -lt $ts_src ] &&  newer="$newer $f"
	done
	[ -n "$newer" ] && \
		echo_yellow "**WARNING: some files are newer than $osaft_rel;" && \
		echo_yellow "# warnings can be ignored if files are cloned or pulled from repository;" && \
		echo_yellow "# checksum may be different for following files:" && \
		echo_yellow "#  $newer"

	echo_info "remove old files in $inst_directory ..."
	for f in $files ; do
		f="$inst_directory/$f"
		if [ -e "$f" ]; then
			echo_info "  rm -f $f"
			$try \rm -f "$f" || __exit 3
		fi
	done

	echo_info "installing $inst_directory ..."
	for d in $osaft_subdirs ; do
		echo_info "  mkdir $inst_directory/$d"
		$try \mkdir -p "$inst_directory/$d"
	done
	for f in $files ; do
		[ -e "$src_directory/$f" ] || echo_red "**ERROR: 043: missing $f; file ignored"
		copy_file "$src_directory/$f"         "$inst_directory/$f"
		check_md5 "$src_directory/$osaft_rel" "$inst_directory/$f"
	done

	echo_info "generate $inst_directory/$osaft_guirc ..."
	if [ -z "$try" ]; then
		w=$(\command -v wish)
		if [ -n "$osaft_gui" -a -n "$w" ]; then
			$try $inst_directory/$osaft_gui --rc > "$inst_directory/$osaft_guirc" \
			|| echo_red "**ERROR: 041: generating $osaft_guirc failed"
		else
			echo_yellow "# missing wish; $osaft_guirc not installed"
		fi
	else
		echo "$inst_directory/$osaft_gui --rc > $inst_directory/$osaft_guirc"
	fi

	if [ -n "$instdev" ]; then
		echo_info "installing $inst_directory ..."
		$try \mkdir -p "$inst_directory/$tst_dir"
		$try \ln  -s . "$inst_directory/$tst_dir"
		for d in $doc_dir $lib_dir $usr_dir; do
			$try \ln -s "../$d" "$inst_directory/$tst_dir/$d"
		done
		for f in $files_install_dev; do
			# already installed file, would result in error
			# TODO: filenames hardcoded
			case "$f" in
			  Dockerfile)         continue; ;;
			  Dockerfile.openssl) continue; ;;
			  o-saft-docker-dev)  continue; ;;
			esac
			_dst="$inst_directory/$f"
				# $tst_dir already part of $f
			echo_info "  cp    $src_directory/$f      $_dst"
			$try \cp    "$src_directory/$f"          "$_dst" \
			|| echo_red "**ERROR: 044: copying $f failed" \
			&& check_md5 "$src_directory/$osaft_rel" "$_dst"
		done
	else
		$try rm -rf $inst_directory/$tst_dir
	fi

	if [ -n "$force" ]; then
		echo_info 'installing RC-FILEs in $HOME ...'
		for f in $inst_directory/$osaft_exerc $inst_directory/$osaft_exerc ; do
			echo_info "  cp    $src_directory/$f $HOME/"
			$try   \cp "$src_directory/$f" "$HOME/" \
			|| echo_red "**ERROR: 042: copying $f failed" \
			&& check_md5 "$src_directory/$osaft_rel" "$HOME/$f"
		done
	fi

	echo_info "generate static help files in $inst_directory ..."
	( $try cd $inst_directory && $try ./$osaft_exe --help=gen-docs )

	echo_info "consider calling:    »$0 --clean $inst_directory«"
	echo_info "installaion details: »$0 --check $inst_directory«"
	if [ 0 -le $err ]; then
		echo_green "# installation in $inst_directory completed."
	else
		echo_error $err
	fi
	return
} # mode_install

mode_openssl () {
	echo_info "mode_openssl() using $build_openssl ..."
	[ ! -x "$build_openssl" ] && echo_red "**ERROR: 020: $build_openssl does not exist; exit" && exit 2
	$build_openssl $optn $@
	status=$?
	if [ $status -eq 0 ]; then
		[ -n "$optv" ] && echo_green "# building openssl completed."
	else
		\cat << EoT
# $build_openssl uses its default settings. To check the settings, use:
#     $0 --openssl --n
# If other configurations should be used, please use directly:
#     $build_openssl --help
#     $build_openssl --n
#     $build_openssl /path/to/install
#     $build_openssl /path/to/install --debian --i --m
EoT
		echo_red   "# building openssl failed."
	fi
	err=$status
	return
} # mode_openssl

mode_cleanup () {
	echo_info "mode_cleanup() ..."
	echo_info "clean-up installation in $inst_directory ..."
	[ -d "$clean_directory" ] || $try \mkdir "$clean_directory/$f"
	[ -d "$clean_directory" ] || $try echo_red "**ERROR: 030: $clean_directory does not exist; exit"
	[ -d "$clean_directory" ] || $try exit 2  # check OK with --n also
	# do not move $usr_dir/ as all examples are right there
	_cnt=0
	files="$files_info $files_ancient $files_develop $files_install_cgi $files_install_doc $files_not_installed"
	for f in $files ; do
		#dbx# echo "$clean_directory/$f"
		[ -e "$clean_directory/$f" ] && $try \rm  -f  "$clean_directory/$f"
		f="$inst_directory/$f"
		[ -e "$f" ] && echo_info "  mv -f    $f $clean_directory" \
		            &&        $try \mv -f "$f" "$clean_directory" \
		            && _cnt=`expr $_cnt + 1`
	done
	for f in $dirs__ancient ; do
		f="$inst_directory/$f"
		[ -d "$f" ] && echo_info "  mv -f    $f $clean_directory" \
		            &&        $try \mv -f "$f" "$clean_directory" \
		            && _cnt=`expr $_cnt + 1`
	done
	echo_info "rm -rf  $inst_directory/$tst_dir"
	$try       rm -rf "$inst_directory/$tst_dir"
	echo_green "# moving $_cnt file(s) to $clean_directory completed."
	err=0
} # mode_cleanup

mode_cgi    () {
	echo_info "mode_cgi() ..."
	echo_info "prepare $inst_directory for use in CGI mode ..."
	cgibin="$inst_directory/cgi-bin" # hardcoded
	htdocs="$inst_directory/htdocs"  # hardcoded
	err=0
	if [ ! -d "$inst_directory" ]; then
		echo_red "**ERROR: 050: $inst_directory does not exist; exit"
		[ -n "$try" ] || exit 2
		# with --n continue, so we see what would be done
	fi
	if [ -d "$clean_directory" ]; then
		echo_red "**ERROR: 051: $clean_directory exist; CGI installation not yet supported"
		exit 2
	fi
	$try \mkdir -p "$cgibin"   # -p avoids error check if dir exists
	$try \mkdir -p "$htdocs"
	# mv files necessary to run tool, leaves all others here (currently hardcoded)
	for f in $osaft_exe doc lib usr ; do
		[ -e "$cgibin/$f" ]    && echo_yellow "# existing $f; ignored" && continue
		f="$src_directory/$f"
		if ! $try \mv $f "$cgibin/" ; then
			echo_red "**ERROR: 052: moving $f failed"
			err=`expr $err + 1`
		fi
	done
	for f in $files_install_cgi ; do
		file=${f##*/}
		[ -e "$htdocs/$file" ] && echo_yellow "# existing $file; ignored" && continue
		f="$src_directory/$f"
		if ! $try \mv $f "$htdocs/" ; then
			echo_red "**ERROR: 053: moving $f failed"
			err=`expr $err + 1`
		fi
	done
	if [ 0 -eq $err ]; then
		echo_green  "# setup  web server: DocumentRoot $htdocs"
		echo_green  "# setup  web server: ScriptAlias  $cgibin"
		echo_green  "# access web server: /o-saft.cgi.html"
		echo_yellow "# consider removing: $src_directory"
		echo_yellow "# consider adapting variable '\$openssl' in $cgibin/o-saft.cgi"
	else
		echo_error $err
		echo_red "# consider reverting installtion in: $htdocs and $cgibin"
	fi
	return
} # mode_cgi

mode_expected () {
	echo_info "mode_expected() ..."
	echo "## Expected output (sample) when called like:"
	echo "##     $0 --check /opt/o-saft"
	\sed -ne '/^#=/s/#=//p' $0
	err=0
	return
} # mode_expected

mode_usage () {
	echo_info "mode_usage() ..."
	\cat << EoUsage

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
	err=0
	return
} # mode_usage

#_____________________________________________________________________________
#_____________________________________________________________________ main __|
new_dir=
while [ $# -gt 0 ]; do
	case "$1" in
	  -h | --h | --help* | '-?' | '/?')
		[ "$1" = "--help" ] && shift  # allow: --help update
		case "$1" in
		  --help=CHECK)  _help CHECK; ;;
		  --help=check)  _help CHECK; ;;
		  --help=UPDATE) _help CHECK; ;;
		  --help=update) _help CHECK; ;;
		  CHECK | check) _help CHECK; ;;
		  UPDATE|update) _help CHECK; ;;
		  *)             _help NAME ; ;;
		esac
		exit 0
		;;
	  '-n' | '--n')         optn="--n"; try=echo; ;;
	  '-v' | '--v')         optv=1;         ;;
	  '-x' | '--x')         set -x;         ;;
	  '--cgi')              mode=cgi;       ;;
	  '--check')            mode=check;     ;;
	  '--clean')            mode=cleanup;   ;;
	  '--install')          mode=install;   ;;
	  '--install-f')        mode=install-f; ;;
	  '--openssl')          mode=openssl;   ;;
	  '--expect')           mode=expected;  ;; # alias
	  '--expected')         mode=expected;  ;;
	  '--checkdev')         mode=checkdev;  ;;
	  '--check-dev')        mode=checkdev;  ;;
	  '--usage')            mode=usage;     ;; # alias
	   --check*)            mode="$1";      ;;
	  '--force')            force="--force";   ;;
	  '--other')            other="--other";   ;;
	  '--instdev')          instdev="--instdev"; ;;
	  '--changes')          changes="--changes"; ;;
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
          '--ignore' | '--i')   ignore="--ignore"; ;;
          '--no-args')          noargs="--noargs"; ;; # alias
          '--noargs')           noargs="--noargs"; ;;
          '--useenv')           useenv="--useenv"; ;;
          '--use-env')          useenv="--useenv"; ;; # alias
          '--gnuenv')           gnuenv="--gnuenv"; useenv="--useenv"; ;;
          '--gnu-env')          gnuenv="--gnuenv"; useenv="--useenv"; ;; # alias
	  '--version')
		\sed -ne '/^#? VERSION/{' -e n -e 's/#?//' -e p -e '}' $0
		exit 0
		;;
	  '+VERSION')   echo 3.75 ; exit;        ;; # for compatibility to $osaft_exe
	  3.75 | 3* | 4*) ;; # ignore version number
	  *)            new_dir="$1"   ;        ;; # directory, last one wins
	esac
	shift
done

if [ -n "$noargs" ]; then
	if [ -n "$useenv" -o -n "$gnuenv" ]; then
		echo_red "**ERROR: 004: --noargs not allowed with --useenv or --gnuenv; exit"
		exit 2
	fi
fi

if [ -n "$osaft_vm_build" ]; then
	case "$mode" in
	  check)    ;; # check is ok
	  --check*) ;; # all --check* are ok
	  *)
	    echo "**ERROR: 001: found 'osaft_vm_build=$osaft_vm_build'"
	    echo_red "**ERROR: 002: inside docker only --check possible; exit"
	    exit 6
	esac
fi

if [ -n "$new_dir" ]; then
	# new dir given, implies --install; not affeced by --install-f
	[ -z "$mode" ] && mode="install"
	inst_directory="$new_dir"
fi
clean_directory="$inst_directory/$clean_directory"
	# set on command line, required for --clean and --cgi

[ -z "$mode" ] && mode="usage"  # default mode
src_txt=
[ "install" = "$mode" ] && src_txt="$src_directory -->"
echo   "$0 $optn $force $_break $ignore $other $changes $noargs $useenv $gnuenv $instdev $inst_directory"
echo_info "$0 3.75 $mode $src_txt $inst_directory "
    # always print internal SID, makes debugging simpler

_b='`'  # using backticks in echo is tricky ...
[ -n "$try" ] && \
	echo "# commands shown in backticks $_b .. $_b may be incomplete."

# check for lock-file, should only exist on author's system
if [ -e "$src_directory/$lock" -o -e "$inst_directory/$lock" ]; then
	_error="**ERROR: 003: development directory; --n enforced"
	case $mode in
	install-f)
		echo_yellow "**WARNING: 003: installing from development directory"
		sleep 5
		mode=install
		;;
	install)
		echo_red "$_error"
		echo_yellow "!!Hint:  003: remove $src_directory/$lock to install or use --install-f"
		try=echo
		;;
	cgi | cleanup)
		echo_red "$_error"
		try=echo
		;;
	esac
fi

_error="**ERROR: 006: can't cd to '$inst_directory'; --n enforced"
# Note: --instdev is not a mode, just an option for --install, hence
#       handled in mode_install()

# generate missing files (quick&dirty, needed for --install, --cgi only)
if [ -e "$osaft_exe" ]; then
	[ -e "$file_cgi_html" ] \
	|| $osaft_exe --no-rc --no-warning --help=gen-cgi  > "$file_cgi_html"
fi
case $mode in
	usage)      mode_usage   ; ;;
	checkdev)   mode_checkdev; ;;
	cleanup)    mode_cleanup ; ;;
	install)    mode_install ; ;;
	openssl)    mode_openssl ; ;;
	expected)   mode_expected; ;;
	cgi)        mode_cgi     ; ;;
	#check)     # see below
 	# parts of check; allow any separator for --check= beside =
	check | --check*)
		PATH=${inst_directory}:$PATH # ensure that given directory is in PATH
		# all checks done in the installation directory
		echo "cd $inst_directory"
		if !  cd $inst_directory 2>/dev/null ; then
			echo_red "$_error"
			try=echo
		fi
		case $mode in
		--check?sid)        check_sids      ; ;;
		--check?SID)        check_sids      ; ;;
		--check?sids)       check_sids      ; ;;
		--check?SIDs)       check_sids      ; ;;
		#--check?ssl)        check_ssl       ; ;;
		#--check?dev)        check_dev       ; ;;
		#--check?doc)        check_doc       ; ;;
		#--check?limit)      check_limit     ; ;;
		--check?tool)       check_tools     ; ;;
		--check?tools)      check_tools     ; ;;
		--check?self)       check_self      ; ;;
		--check?perl)       check_perl      ; ;;
		--check?modules)    check_modules   ; ;;
		--check?rc)         check_rc        ; ;;
		--check?inst)       check_inst      ; ;;
		--check?summary)    check_summary   ; ;;
		--check?openssl)    check_openssl   ; ;;
		--check?pod)        check_podtools  ; ;;
		--check?podtools)   check_podtools  ; ;;
		--check?usr)        check_usr       ; ;;
		# simple mode=check itself
		check)              mode_check      ; ;;
		esac
		;;
	*)          err=5; echo_red "**ERROR: 060: unknow mode  $mode; exit"; ;;
esac

exit $err

