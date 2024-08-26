#!/usr/bin/make -rRf
#?
#? NAME
#?      Makefile        - makefile for testing O-Saft
#?
#? SYNOPSYS
#?      make [options] [target] [...]
#?
#? DESCRIPTION
#?      For more details please see
#?          ../Makefile  Makefile.help  Makefile.pod
#?      make help.test
#?
# HACKER's INFO
#    Naming conventions for t/Makefile*
#       * variable names have the prefix  TEST  and  HELP .
#       * target names for public use have the prefix  test.
#       * individual, special targets have the prefix  _test (exceptions exist)
#
#    Summary variables extended in each t/Makefile*
#       ALL.includes    - list of Makefiles
#       ALL.inc.type    - list of types (should be suffix of Makefile's name)
#       ALL.help.tests  - list of documentation (help) texts
#       ALL.tests       - list of targets for testing
#       ALL.tests.log   - list of targets for testing writing to logfile
#
#    Variables specific for each t/Makefile*
#       O-SID.myTYPE    - version number
#       O-SELF.myTYPE   - name of current file
#       HELP.myTYPE     - documentation (help) text for the corresponding file
#       HELP.myTYPE.all - list of all targets for the corresponding file
#       HELP.myTYPE.internal  - some more documentation (help) text
#           where  myTYPE  above is the suffix of the Makefile's filename
#
#    Each t/Makefile* may also redefine following variables
#       HELP_TYPE       - suffix (and type) of Makefile*
#       HELP_HEAD       - descriptive header line, set to HELP_NAME, HELP_RULE 
#
#    Special targets for documentation (help) in t/Makefile*
#       help.test.%     - print individual documentation using $(HELP.myTYPE)
#       help.test.%.all - print all targets using $(HELP.myTYPE.all)
#       help.test.%.internal - print details using $(HELP.myTYPE.internal)
#           where  %  is the suffix of the Makefile's filename
#
#       TODO:
#          * include Makefile.* should be generic
#          * unify test.warnings.log and test.tests.log (should use same target)
#          * rename ALL.tests and ALL.tests.log (too similar to ALL.test)
#
#? VERSION
#?      @(#) Makefile 3.22 24/08/27 01:06:46
#?
#? AUTHOR
#?      18-apr-18 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

HELP-help.test.test = general testing targets

O-SID.test         := 3.22
O-SELF.test        := t/Makefile
ALL.includes       += $(O-SELF.test)
ALL.inc.type       += test
ALL.help.tests     += help.test

export LANG        := C
export LC_CTYPE    := C.UTF-8
    # LANG ensures same messages and sorting everywhere  
    # LC_CTYPE should ensures that all characters are proper encoded
ifeq ($(MAKELEVEL),0)
    export PATH    := .:..:./usr:../usr:$(PATH)
    # ensure that our tools are found in our directories first
    # then use given PATH as we don't know where to find common tools
    # only set i top-most make to avoid duplicate paths
endif
export OSAFT_MAKE  := avoid writing random data (like date and time string)
export OSAFT_OPTIONS  ?= --trace-CLI
    # OSAFT_OPTIONS=--trace-CLI because the command line should be printed
    # always in each EXE.pl call; may be redifened on make's command line
test%VERSION:   OSAFT_OPTIONS=
    # these targets should not print command line with --trace-CLI

first-test-target-is-default: help.test

ifndef ALL.Makefiles
    -include t/Makefile.inc
    # defines variables if called directly (not from ../Makefile)
endif

help.test:            HELP_TYPE = test
help.test-v:          HELP_TYPE = test
help.test-vv:         HELP_TYPE = test
help.test.all:        HELP_TYPE = test
help.test.test:       HELP_TYPE = test
help.test.test-v:     HELP_TYPE = test
help.test.test-vv:    HELP_TYPE = test
help.test.test.all:   HELP_TYPE = test
help.test:            HELP_HEAD = $(HELP_RULE)
help.test.%:          HELP_HEAD = $(HELP_RULE)

#_____________________________________________________________________________
#________________________________________________________________ variables __|

ifndef TEST.remove-environment-variables
    # most environment variables should be ignored,  to avoid unexpected
    # behaviour and to keep our list of variables clean;
    # first define list of required variables, then get list of existing
    # environment variables and remove all except the required ones
    # PERL5LIB and PERL_HASH_SEED are removed also because used internal
    $(eval _keep =      LANG    LC_ALL  LC_CTYPE \
	OSAFT_CONFIG    OSAFT_MAKE      OSAFT_OPTIONS \
        DISPLAY HOME    PATH    PWD     SHELL   TERM    USER    NLSPATH \
        DT_RUNPATH      DT_RPATH DT_NEEDED \
        DYLD_LIBRARY_PATH   DYLD_FALLBACK_LIBRARY_PATH \
        LD_CONFIG       LD_LIBRARY_PATH LD_PRELOAD      LD_RUN_PATH LD_DEBUG \
        LD_TRACE_LOADED_OBJECTS   LD_TRACE_LOADED_OBJECTS_ALL LD_TRACE_PRELINKING \
        LIBPATH RPATH   RUNPATH   SHLIB_PATH  \
        OPENSSL_CONF    OPENSSL_FIPS    OPENSSL_ENGINES OPENSSL \
        OPENSSL_ALLOW_PROXY OPENSSL_ALLOW_PROXY_CERTS \
    )
    $(eval _env  = $(shell printenv | awk -F= '{print $$1}'))
    $(foreach _var, $(filter-out $(_keep),$(_env)), $(eval undefine $(_var)))
    $(eval undefine _keep)
    $(eval undefine _env)
    TEST.remove-environment-variables = done
endif

# store -n (dry-run) option in own variable
TEST.make-n    := $(if $(findstring n,$(firstword -$(MAKEFLAGS))),-n)

# internal variables
TEST.dir       := t
TEST.logdir    ?= $(TEST.dir)/log
TEST.logtxt    := <<random value replaced by make>>
TEST.symlinks  := ../usr ../lib ../.o-saft.pl ../docs
TEST.tmpdir    ?= /tmp/$(O-Project)
TEST.tmp.rc    ?= $(TEST.tmpdir)/.rc

# following may be redefined in any included t/Makefile*
#TEST.init      := --header
#TEST.args      :=

# variable for list of hostnames needs to be unique in each Makefile*
# otherwise some targets in other Makefile* get confused
#TEST.host       = localhost
#TEST.hosts      =

# following defined in ../Makefile
# TEST.exe =
# SRC.test =
# ALL.test =

# defined in other t/Makefile*
# ALL.tests =

# $(SRC.rc)  may not be defined here, hence hardcoded

# Tracing just the log-targets is special. Using $(O-TRACE.target) is not an
# option, because it would als change the final target called with  $(MAKE) .
# Hence an additional variable is used.
# TODO: not public, not documented, variable needs to be defined here
O-TRACE.target.log  =
    # example  = echo "\# $*\tcalling: $(MAKE) -s testcmd-$*"

TEST.today         := $(shell date +%Y""%m%d)
    # current date in ISO format

# need a usable way to change diff program; EXE.diff may be set on command-line
EXE.log-diff       := diff
EXE.log-xxdiff     := xxdiff --geometry 1600x1000
EXE.log-mgdiff     := mgdiff
EXE.log-tkdiff     := tkdiff
EXE.diffs          := diff xxdiff mgdiff tkdiff
EXE.diff           := tkdiff
EXE.log-diff        = $(EXE.log-tkdiff)
    # change EXE.log-diff to use another program

# need a usable way to change generator for man-pages
EXE.gendoc.perldoc := perldoc
EXE.gendoc.pod2man := pod2man
EXE.gendoc         := $(EXE.gendoc.perldoc)

# default filter for testarg-%.log targets
EXE.log-filterarg  := cat
# default filter for testcmd-%.log targets
EXE.log-filtercmd  := cat

_EXE.grep-opt      := -q
    # grep (mainly used in message-% target) should not report matching lines
    # variable can be reset or redifined for more verbose output

_EXE.sort-opt      := -n -f
    # newer GNU sort (~2018) changed the default behaviour, for example
    # case-sensitivity, these options do the traditional sort
    # TODO: need to check first if sort supports these options

_EXE.perldoc-opt   := -n nroff -T
    # newer perldoc prints with plain text format by default
    # -n nroff enforced the traditional behaviour with ASCII-escapes

_EXE.pod2man-opt   := --utf8
    # --date=DATESTRING
    # will be used for testing to avoid diff in generated files

# define script or parts of it as variables, for better human readability
# SEE Make:target matching
#     _EXE.macro_by_line.awk    - extract all variable names
#     _EXE.target_by_line.awk   - extract all target names
#     _EXE.target_to_arr.awk    - extract target names and store uniquely in arr[]
#     _EXE.print_arr_END.awk    - print collected data from arr[]
#     _EXE.print_file.awk       - either print separator line or the filename
TEST.target_prefix     := [a-zA-Z][_a-zA-Z.]
   # matching target names not starting with _
_EXE.macro_by_line.awk := /^[a-zA-Z_][a-zA-Z_.]* *=/{sub(/=/,"",$$1);print $$1}
_EXE.target_by_line.awk:= /^[a-zA-Z_][a-zA-Z_.]* *:/{sub(/:/,"",$$1);print $$1}
_EXE.target_to_arr.awk  = /^.*%/{next} /^$(TEST.target_prefix)*/{arr[$$1]=1}
_EXE.print_arr_END.awk := END{for(idx in arr){print idx}}
_EXE.print_file.awk    := (FNR==1){ x="";for(i=1;i<62;i++){x=sprintf("%s%c",x,"-")};print "\n\t\t\#"x}

# O-TRACE.target is not empty if target was  test*-compare-v or test*-move-v .
# So it is sufficent to check if  O-TRACE.target is not empty to print verbose
# information.
# TODO: not tested if following defines could be written as macros
# SEE Make:defines with commands

define EXE.log-compare
	cd $(TEST.logdir) && \
	echo "# compare "`ls $(TEST.target_prefix)*.log$(TEST.log-suffix) | wc -l`" file ..." && \
	for f in $(TEST.target_prefix)*.log; do \
	    [ -f $${f}$(TEST.log-suffix) ] || continue ; \
	    [ -n '$(O-TRACE.target)' ] && echo "# $(TEST.logdir)/$${f} ..." ; \
	    $(EXE.log-diff) $${f} $${f}$(TEST.log-suffix) >/dev/null 2>&1 ; \
	done ; \
	exit 0
endef

define EXE.log-compare-hint
	echo ""
	echo "# for informations and to show differences with $(EXE.diff), use:"
	echo "    $(MAKE_COMMAND) help.test.log-info"
	echo "    $(MAKE_COMMAND) $(MAKECMDGOALS)-compare"
	echo "    $(MAKE_COMMAND) $(MAKECMDGOALS)-compare-v"
	echo "    $(MAKE_COMMAND) $(MAKECMDGOALS)-compare TEST.log-suffix=$(TEST.log-suffix)"
endef

define EXE.log-move
	cd $(TEST.logdir) && \
	for f in $(TEST.target_prefix)*.log; do \
	    [ -f $${f}$(TEST.log-suffix) ] || continue ; \
	    [ -n '$(O-TRACE.target)' ] && echo "# $(TEST.logdir)/$${f} ..." ; \
	    mv $${f}$(TEST.log-suffix) $${f} ; \
	done ; \
	exit 0
endef

# FIXME: does not set _stub properly if $* is set
define EXE.log-move-hint
	_stub="log"
	$(eval _stub="log")
	$(eval $(shell [ -n "$*" ] && _stub="$*.log" ))
	echo ""
	echo "# for informations and to move new files to .log , use:"
	echo "    $(MAKE_COMMAND) help.test.log-info"
	echo "    $(MAKE_COMMAND) test.$(_stub)-move"
	echo "    $(MAKE_COMMAND) test.$(_stub)-move TEST.log-suffix=$(TEST.log-suffix)"
endef

# EXE.log-make_or_print simply prints instead of executing sub-make
# Usage: $(call EXE.log-make_or_print,target-name,EXE-filter-varibalename)
# keep in mind that 'echo "$(MAKEFLAGS)x"' is used to force grep to return
# status in case of $(MAKEFLAGS) being empty
# using a sub-shell (..) requires using \ to avvoid sh syntax errors
define EXE.log-make_or_print
        ( \
          echo "$(MAKEFLAGS)x" | awk '($$1~/n/) {exit 1}' >/dev/null || \
          echo "$(MAKE) $(MFLAGS) -s $(1)" ; \
          echo "$(MAKEFLAGS)x" | awk '($$1~/n/) {exit 1}' >/dev/null && \
                $(MAKE) $(MFLAGS) -s $(1) 2>&1 | $($(2)) ; \
        )
endef

HELP.test       = $(O-NL)\
\# The term '%'  in the targets names described here, may be any of:$(O-NL)\
\#   $(ALL.inc.type)$(O-NL)\
\#$(O-NL)\
\# Following variables are intended to be used on command line:$(O-NL)\
\#   EXE.pl      - program to perform tests, default: '$(EXE.pl)'$(O-NL)\
\#   TEST.init   - arguments and options always passed to EXE.pl; default: '$(TEST.init)'$(O-NL)\
\#   TEST.args   - arguments and options to be  passed to EXE.pl per target$(O-NL)\
\#   TEST.host   - hostname to be used for tests (when only one is expected)$(O-NL)\
\#   TEST.hosts  - list of hostnames to perform tests with$(O-NL)\
\#   TEST.dir    - directory in which EXE.pl will be executed; default: '$(TEST.dir)/'$(O-NL)\
\#   TEST.logdir - directory where results of EXE.pl will be stored; default: '$(TEST.logdir)/'$(O-NL)\
\#   TEST.rc     - content of RC-file to be used by EXE.pl: '$(TEST.rc)'$(O-NL)\
\#   TEST.target_prefix - prefix of log-filename; see help.test.log-info$(O-NL)\
\#   TEST.log-suffix    - suffix of log-filename; see help.test.log-info$(O-NL)\
\#$(O-NL)\
\# Notes about some spezial targets:$(O-NL)\
\#   help.test   - automatically generated target; alias for help.test.test$(O-NL)\
\#   help.test.test.alls -$(O-NL)\
\#   help.test.test.all - be prepared for huge output$(O-NL)\
\#$(O-NL)\
\# Keep in mind that following files are located in '$(TEST.dir)/':$(O-NL)\
\#   .o-saft.pl  $(TEST.rc)  .o-saft.tcl$(O-NL)\
\# which are used by EXE.pl or other tools used for the tests.

# following variable contains (huge) list of all available targets
HELP.test.test.all  = $(O-NL)\
\# $(words $(ALL.tests)) targets for tests:$(O-NL)\
$(ALL.tests)$(O-NL)\
\#$(O-NL)\
\# $(words $(ALL.tests.log)) targets which write results to logfiles:$(O-NL)\
$(ALL.tests.log)$(O-NL)\
\#$(O-NL)\
\# summary targets for tests:$(O-NL)\
$(ALL.help.tests:help.%=%)$(O-NL)\
\#$(O-NL)\
\# for more details of the targets, following targets can be used:$(O-NL)\
$(foreach target,$(ALL.inc.type),t-$(target))$(O-NL)

HELP.test.test  = $(HELP.test)
HELP.test.all   = $(HELP.test.test.all)
help.test:          help.test.test
help.test.all:      help.test.test.all
	@$(O-TRACE.target)
# convenience to satisfy  help.test.all

help.tests:           HELP_TYPE = test
help.tests:           HELP_HEAD = $(HELP_RULE)
help.tests:         help.test.test
    # convenience alias for  help.test

# help.test.test would only print the  HELP-*  texts from herein.
# All other tests from the individual t/Makefile.* files have their own  HELP-*
# variable their. help.test.test should also print hints how to get information
# about these other targets. Therefore the auxiliary target  _help_list  exists
# in  Makefile  which is used as dependency here.
help.test.test:     _help_list
help.test.test-v:   _help_list
help.test.test-v-v: _help_list

#_____________________________________________________________________________
#____________________________________________ target for help in t/Makefile*__|

HELP-help.test.test.all     = print available targets for tests from all Makefiles
HELP-help.test.test.alls    = print available targets for tests one per line
#HELP-help.test.test.all-n   = show command for all available test targets
HELP-help.test.%.all        = print available individual targets for tests '%' from Makefile.*
HELP-help.test.%.internal   = show settings for tests '%' from Makefile.*
HELP-help.test.targets      = print all available targets for tests; followed by targets sorted by Makefile*

# experimental: some targets print too many shell commands
help.test.test.all-n:
	@$(O-TRACE.target)
	@$(MAKE) -n $(ALL.tests)

# following roughly the same as "make s-ALL.tests"
help.test.test.alls:
	@$(O-TRACE.target)
	@echo " # $(words $(ALL.tests)) targets for tests:"
	@echo $(ALL.tests) | $(EXE.wordperline) | sort $(_EXE.sort-opt)
	@echo ""

help.test.%.all:
	@$(O-TRACE.target)
	@echo " # individual targets for testing $* :"
	@echo $(ALL.test.$*) | $(EXE.wordperline) | sort $(_EXE.sort-opt)
	@echo ""
	@echo "$(HELP.test.$*.all)"

help.test.%.internal:
	@$(O-TRACE.target)
	@echo " # TEST.file:       $(TEST.file)"
	@echo " # TEST.init.$*:    $(TEST.init.$*)"
	@echo " # TEST.$*.hosts:   $(TEST.$*.hosts)"
	@echo " # ALL.test$*:     $(words $(ALL.test$*))  : $(ALL.test$*)"
	@echo " # ALL.test.$*:    $(words $(ALL.test.$*)) : $(ALL.test.$*)"
	@echo $(HELP.$*.internal)
	@echo " # -------------------------------------------------------------"

ALL.help.tests.all      = $(foreach type,$(ALL.inc.type), help.test.$(type).all)
ALL.help.test.internal  = $(foreach type,$(ALL.inc.type), help.test.$(type).internal)
help.test.targets:
	@$(MAKE) -s $(ALL.help.tests.all) $(ALL.help.test.internal)

#_____________________________________________________________________________
#_____________________________________________________ internal test target __|

HELP-_internal  = _____________________________________ internal test target _
HELP-testcmd-test.internal = print GNU Make's internals and global project settings
# dummy ' to keep some stupid syntax highlighting happy
HELP-help.test.makevars = print all variables

# internal information (nothing related to $(O-Project))
# NOTE: $(O-SID*) variables indicate if a t/Makefile* was included.
# NOTE: $$  needs to be used to ensure that the variables are evaluated when
#       the target executes and not when the Makefile is read.
# NOTE: when target testcmd-test.internal is called with  -n ; the command:
#           @echo '# $$(MAKE)          = $(MAKE)'
#       will produce output:
#           # $(MAKE)          = make
#       SEE GNU Make:MAKE vs. MAKE_COMMAND
# TODO: list of $(O-SID.*) should be generated using $(ALL.inc.type)

# Makefile and Makefile.pod are nowhere included, hence their O-SID is missing
# here and must be exracted from the file directly, ugly workaround ...
ifndef O-SID
    O-SID       = $(shell awk '($$1=="O-SID"){print $$3}' ../Makefile)
endif
ifndef O-SID.pod
    O-SID.pod   = $(shell awk '($$1=="@(#)"){print $$3}' t/Makefile.pod)
endif
#   O-SID.TEMPL = missing, as it is not so important

# next 3 empty targets are dummies to get values for $< $? $^ and $+
test.file-1:
test,file-2:
test_file-3:
testcmd-test.internal: test.file-1 test,file-2 test_file-3
	@$(O-TRACE.target)
	@echo 'testcmd-test.internal: test.file-1 test-file-2 test_file-3'
	$(foreach _v,$(filter O-SID%,$(sort $(.VARIABLES))), \
		$(eval _sids += $(_v)) \
	 )
	@echo '# found O-SID.*     = $(_sids)'
	@echo '# SIDs of included Makefile* (file not included if SID missing):'
	@echo '# $$(O-SID)          = $(O-SID)'
	@echo '# $$(O-SID.help)     = $(O-SID.help)'
	@echo '# $$(O-SID.test)     = $(O-SID.test)'
	@echo '# $$(O-SID.critic)   = $(O-SID.critic)'
	@echo '# $$(O-SID.warnings) = $(O-SID.warnings)'
	@echo '# $$(O-SID.cipher)   = $(O-SID.cipher)'
	@echo '# $$(O-SID.make)     = $(O-SID.make)'
	@echo '# $$(O-SID.exit)     = $(O-SID.exit)'
	@echo '# $$(O-SID.init)     = $(O-SID.init)'
	@echo '# $$(O-SID.inst)     = $(O-SID.inst)'
	@echo '# $$(O-SID.misc)     = $(O-SID.misc)'
	@echo '# $$(O-SID.cmd)      = $(O-SID.cmd)'
	@echo '# $$(O-SID.dev)      = $(O-SID.dev)'
	@echo '# $$(O-SID.mod)      = $(O-SID.mod)'
	@echo '# $$(O-SID.etc)      = $(O-SID.etc)'
	@echo '# $$(O-SID.ext)      = $(O-SID.ext)'
	@echo '# $$(O-SID.cgi)      = $(O-SID.cgi)'
	@echo '# $$(O-SID.gen)      = $(O-SID.gen)'
	@echo '# $$(O-SID.hlp)      = $(O-SID.hlp)'
	@echo '# $$(O-SID.inc)      = $(O-SID.inc)'
	@echo '# $$(O-SID.opt)      = $(O-SID.opt)'
	@echo '# $$(O-SID.pod)      = $(O-SID.pod)'
	@echo '# $$(O-SID.tcl)      = $(O-SID.tcl)'
	@echo '# $$(O-SID.docker)   = $(O-SID.docker)'
	@echo '# $$(O-SID.legacy)   = $(O-SID.legacy)'
	@echo '# $$(O-SID.TEMPL)    = $(O-SID.TEMPL)'
	@echo '# show some private make variables:'
	@echo '# $$(PWD)           = $(PWD)'
	@echo '# $$(PWD.dir)       = $(notdir $(PWD))'
	@echo '# $$(ALL.includes)  = $(ALL.includes)'
	@echo '# $$(ALL.inc.type)  = $(ALL.inc.type)'
	@echo '# $$(TEST.dir)      = $(TEST.dir)'
	@echo '# $$(TEST.logdir)   = $(TEST.logdir)'
	@echo '# $$(TEST.host)     = $(TEST.host)'
	@echo '# $$(TEST.hosts)    = $(TEST.hosts)'
	@echo '# $$(ALL.Makefiles) = $(ALL.Makefiles)'
	@echo '# show some make variables:'
	@echo '# $$@    = $@ #'
	@echo '# $$<    = $< #'
	@echo '# $$?    = $? #'
	@echo '# $$^    = $^ #'
	@echo '# $$+    = $+ #'
	@echo '# $$|    = $| #'
	@echo '# $$%    = $% #'
	@echo '# $$*    = $* #'
	@echo '# $$>    = $> #'
	@echo '# $$-    = $- #'
	@echo '# $$D    = $D #'
	@echo '# $$F    = $F #'
	@echo '# $$T    = $T #'
	@echo '# not shown: $$(%D) $$(?D) $$(@D) $$(*D) $$(<D) $$(?D) $$(^D) $$(%F) $$(?F) $$(@F) $$(*F) $$(<F) $$(?F) $$(^F)'
	@echo '# $$(MAKE)          = $(MAKE)'
	@echo '# $$(CURDIR)        = $(CURDIR)'
	@echo '# $$(MAKE_COMMAND)  = $(MAKE_COMMAND)'
	@echo '# $$(MAKE_VERSION)  = $(MAKE_VERSION)'
	@echo '# $$(MAKE_HOST)     = $(MAKE_HOST)'
	@echo '# $$(MAKE_RESTARTS) = $(MAKE_RESTARTS)'
	@echo '# $$(MAKE_TERMERR)  = $(MAKE_TERMERR)'
	@echo '# $$(MAKE_TERMOUT)  = $(MAKE_TERMOUT)'
	@echo '# $$(MFLAGS)        = $(MFLAGS)'
	@echo '# $$(MAKEFLAGS)     = $(MAKEFLAGS)'
	@echo '# $$(MAKEINFO)      = $(MAKEINFO)'
	@echo '# $$(MAKELEVEL)     = $(MAKELEVEL)'
	@echo '# $$(MAKEFILE)      = $(MAKEFILE)'
	@echo '# $$(MAKEFILES)     = $(MAKEFILES)'
	@echo '# $$(MAKEFILE_LIST) = $(MAKEFILE_LIST)'
	@echo '# $$(MAKEFILE_LIST)F= $(firstword $(MAKEFILE_LIST))'
	@echo '# $$(MAKEFILE_LIST)L= $(lastword  $(MAKEFILE_LIST))'
	@echo '# $$(MAKEOVERRIDES) = $(MAKEOVERRIDES)'
	@echo '# $$(MAKECMDGOALS)  = $(MAKECMDGOALS)'
	@echo '# $$(GNUMAKEFLAGS)  = $(GNUMAKEFLAGS)'
	@echo '# $$(.DEFAULT_GOAL) = $(.DEFAULT_GOAL)'
	@echo '# $$(.DELETE_ON_ERROR)= $(.DELETE_ON_ERROR)'
	@echo '# $$(.EXTRA_PREREQS)= $(.EXTRA_PREREQS)'
	@echo '# $$(.IGNORE)       = $(.IGNORE)'
	@echo '# $$(.INCLUDE_DIRS) = $(.INCLUDE_DIRS)'
	@echo '# $$(.INTERMEDIATE) = $(.INTERMEDIATE)'
	@echo '# $$(.NOTINTERMEDIATE)= $(.NOTINTERMEDIATE)'
	@echo '# $$(.NOTPARALLEL)  = $(.NOTPARALLEL)'
	@echo '# $$(.ONESHELL)     = $(.ONESHELL)'
	@echo '# $$(.POSIX)        = $(.POSIX)'
	@echo '# $$(.PRECIOUS)     = $(.PRECIOUS)'
	@echo '# $$(.RECIPEPREFIX) = $(.RECIPEPREFIX)'
	@echo '# $$(.SECONDARY)    = $(.SECONDARY)'
	@echo '# $$(.SHELLFLAGS)   = $(.SHELLFLAGS)'
	@echo '# $$(.SILENT)       = $(.SILENT)'
	@echo '# $$(.SUFFIXES)     = $(.SUFFIXES)'
	@echo '# $$(.FEATURES)     = $(.FEATURES)'
	@echo '# $$(.VARIABLES)    = $(words $(.VARIABLES)) variables'
	@echo '#                    huge list .VARIABLES not shown (includes own names),'
	@echo '#                    use: make help.test.makevars'
	@echo '# folowing variables are not printed because'
	@echo '#     different for each call:     MAKE_TERMOUT  MAKE_TERMERR'
	@echo '#     most likely not a variable: .DEFAULT  .PHONY  .SECONDEXPANSION'

# TODO taget testcmd-test.internal-v does not work

# TODO (2022) not yet added to proper variables
ALL.help.test      += testcmd-test.internal
ALL.tests          += testcmd-test.internal

help.test.makevars:
	@echo '# $$(.VARIABLES)    = '
	@echo '$(.VARIABLES)' | $(EXE.wordperline) | sort $(_EXE.sort-opt)

.PHONY: help.test.makevars

#_____________________________________________________________________________
#______________________________________________________ targets for testing __|

# Tests are started in $(TEST.dir) which is ./t/ usually, and calls the tools
# most likely like ../tool . Therefore we need  ..  in Perl's list of include
# paths also. Using the environment variable PERL5LIB ensures that it will be
# added while testing with Makefiles only.
test%:  export PERL5LIB        := ..
test%:  export PERL_HASH_SEED  := cafe
    # SEE Note:Testing, sort

# FIXME: missing public (not internal) documentation for pattern rules:
#       message-%:
#       no.message-%:
#       testarg-%:
#       testcmd-%
#       test.all-%:

$(TEST.logdir):
	@mkdir $@

HELP-test.links = create required symbolic links in '$(TEST.dir)'
# Creating links is scary, fails if they exist; therefore ln --force is used,
# but this may destroy existing links or files silently.
# Because the target itself is never created, it will always be executed. Use
# this target (rule)  with care!
../%:
	@$(O-TRACE.target)
	cd $(TEST.dir) && ln --force -s $@

test.links: $(TEST.symlinks)

# target to check for empty hostname list, can also be used for more debugging
_no-hosts__not-yet-working:
	@[ "$(eTEST.hosts)" = "" ] && $(eval _ERR := "no TESTS.hosts defined")
	@[ "$(eTEST.hosts)" = "from.Makefile.FQDN" ] \
		&& $(eval _ERR := "fake TESTS.hosts defined in $(TEST.file)")
	@[ -n "$(_ERR)" ] && echo $(_ERR) && exit 2  || echo -n ""

_no-hosts:
	@-[ "$(eTEST.hosts)" = "" ] \
		&& echo no TESTS.hosts defined \
		&& exit 2 \
		|| echo -n ""
	@-[ "$(eTEST.hosts)" = "from.Makefile.FQDN" ] \
		&& echo fake TESTS.hosts defined in $(TEST.file) \
		&& exit 2 \
		|| echo -n ""

.PHONY: _no-hosts

_FORCE:

# = message-% =
# Testing for messages or other strings (i.e **WARNING) works as follows:
#   call $(EXE.pl) with command and/or options in question
#   then search (grep) output for message (string)
#
# Some tests are not yet implemented, or difficult to implement. In this case
# $(TEST.args) contains a string starting with "TODO:". The  message-% target
# tests the variable for this string and then simply prints it. Otherwise the
# check will be performed (see  if - else - fi  in message-% rule).
# The pattern rule succeeds (returns status 0)  if the pattern is found.  The
# rule fails, if the pattern is not found. That's why it is very important to
# define  TEST.args  propperly. Even the sequence of the arguments may count.
#
# NOTE: the called $(EXE.pl) may return the expected pattern given by the  $*
# pattern multiple times, even in not intended output. In this case, the rule
# succeeds also, as the pattern is found in the output. Example:
#       make message-unintended TEST.args="host-unintended +cn"
#
# For some behaviours of $(EXE.pl) a RC-file is required.
# NOTE: even  TEST.tmp.rc  may be generated for some targets, it will only be
# used when requested with the  --rc=$(TEST.tmp.rc)  option.
#
# Different target rules can be mapped to the pattern rule message-%. It gets
# the message string  from the automatic variable  $* , and all arguments for
# $(EXE.pl) with following Makefile variables:
#   $(TEST.init)    - command, options to be passed to $(EXE.pl)
#   $(TEST.args)    - command, options and hostname to be passed to $(EXE.pl)
#   $(TEST.rc)      - content of RC-file to be used by $(EXE.pl)
# These variables can be set conditinally for each target, see example below.
#
# Example of Usage
#       pattern rule:   warning-%
#       target rule:    warning-049
#       pattern:        049
#       arguments:      TEST.args = +unknown_command +quit
#   Example for the target rule with above settings will be:
#       warning-%:      EXE.pl      = ../$(SRC.pl)
#       warning-%:      TEST.init   = --init-option
#       warning-049:    TEST.args   = +unknown_command +quit
#   Map all pattern rules to message-% pattern rule (recipe need command)
#       warning-%: message-%
#               @echo -n ""
#   The recipe in the pattern rule message-% will be:
#       $(EXE.pl)    $(TEST.init)  $(TEST.args)           2>&1 | grep 049
#   which finally evaluates to:
#       ../o-saft.pl --init-option +unknown_command +quit 2>&1 | grep 049
#                     +quit  command or  other command and hostname is needed
#                     for testing the warning message
#
# NOTE:  if  TEST.args  contains special characters,  syntax errors may occur
# when used in the shell. Quoting  TEST.args  is not possible because then it
# becomes a single argument instead of discrete arguments. At least following
# special characters should not be used:  ; & | # < > ` [ ]

# target succeeds if message is there
message-%:
	@$(O-TRACE.target)
	@-if expr "$(TEST.args)" ":" "^TODO" >/dev/null ; then \
	    echo "$@:    $(TEST.args)"; \
	else \
	    echo "$(TEST.rc)" > $(TEST.tmp.rc) ; \
	    echo "cd $(TEST.dir) && $(EXE.pl) $(TEST.init) $(TEST.args) 2>&1 | grep $(_EXE.grep-opt) $* " ; \
	    cd $(TEST.dir) && $(EXE.pl) $(TEST.init) $(TEST.args) 2>&1 | grep $(_EXE.grep-opt) $* ; \
	    _status=$$? ; \
	    rm -f $(TEST.tmp.rc) ; \
	    exit $$_status ; \
	fi
# following removed from above, too noicy:
#            echo "echo '$(TEST.rc)' > $(TEST.tmp.rc)" ;

# target succeeds if message is missing
# TODO: need more examples beside those in t/Makefile.cgi
no.message-%:
	@$(O-TRACE.target)
	@echo "$(TEST.rc)" > $(TEST.tmp.rc)
	cd $(TEST.dir) && $(EXE.pl) $(TEST.init) $(TEST.args) 2>&1 | awk '/ $*/{exit 1}'
	@rm -f $(TEST.tmp.rc)

# = testarg-% =
# Simple target to calL: $(EXE.pl) $(TEST.init) $(TEST.args)
testarg-%:
	@$(O-TRACE.target)
	-cd $(TEST.dir) && $(EXE.pl) $(TEST.init) $(TEST.args)

# = testcmd-% =
# The goal for test targets is to perform (test) all commands with all hosts.
# The hostnames are provided in a simple list: $(TEST.hosts) .
# The commands could not be provided in a make variable all together,  because
# each command may consist of space separated words like:  "+info --header".
# Hence each command is defined in the variable  TEST.args,  which will be set
# for an individual target, for example:  testcmd-001 .There is one target for
# each specific test case,  which actually is a list of  commands and  options
# for the tool $(EXE.pl) . Note that the trailing  DDD  (001 in example above)
# is just a number to make each target unique.
# To feed the hostname to that target,  the target is defined as  pattern rule
# testcmd-001_% , which means that the hostname can be passed like:
#       testcmd-001_host.some.tld
# Now we can simply use:  $(TESTS.hosts:%=testcmd-001_%) , which generates one
# target for each host in the list. But that would require to build a list for
# each such target:  testcmd-002_%  and  testcmd-003_%  and so on.
# As we want to perform all these targets with all hostnames,  this would also
# require  an additional pattern rule for the hostname part.  To avoid such an
# addditional pattern rule for each  testcmd-DDD,  the general  pattern rule
# testcmd-%  is used.  It handles all the individual targets which contain the
# hostname.
# Unfortunately, this pattern contains DDD_ (for example 001_host.some.tld) as
# hostname. This  DDD_  prefix must then be removed in the target command, the
# $(shell awk ...)  does the dirty work. in detail (as defined below):
#       # pattern rule to handle all targets testcmd-DDD_HOSTNAME
#       testcmd-%:
#       #
#       # remove prefix  DDD-  from hostname
#       $(shell awk 'END{h="$*";sub(/^[^_]*-/,"",h);print h}' /dev/null)
#       # or
#       $(shell echo "$*" | awk -F_ '{print $$2}') $(TEST.args)
#       #   c00-aa.tld returns: aa.tld
#
# NOTE: following does not work proper (in GNU Make), hence the solution above:
#       testcmd-no1: TEST.args  = +quit $*
#       testcmd-no2: TEST.args := +quit $*
#
# Example of Usage
#       pattern rule:   testcmd-%
#       target rule:    testcmd-c00
#       pattern:        00c_aa.tld
#       arguments:      TEST.args = +cipher
#       hosts tested:   aa.tld  bb.tld
#   Example for the target rule in t/Makefile.* with above settings will be:
#       # define list of hostnames
#       TEST.hosts      = aa.tld  bb.tld
#       # define targets
#       testcmd-c%:     EXE.pl      = ../$(SRC.pl)
#       #   EXE.pl must be defined wherever testcmd-% is used/referenced
#       testcmd-c%:     TEST.init   = --header
#       #
#       # define the commands to be used for $(EXE.pl) in the target
#       testcmd-c00_%:  TEST.args   += +cipher --enabled
#       testcmd-c01_%:  TEST.args   += +info
#       #
#       # dynamically generate list of all testcmd-DDD  targets
#       ALL.ext.cmd     = $(shell awk -F_ '/^testcmd-c[0-9]/{print $$1}' t/Makefile.ext)
#       #   returns: testcmd-c00 testcmd-c01
#       #
#       # dynamically generate list of all testcmd-DDD for all hostnames
#       ALL.by_host     = $(foreach host,$(TEST.hosts),$(ALL.ext.cmd:%=%_$(host)))
#       #   returns: testcmd-c00_aa.tld testcmd-c01_aa.tld testcmd-c00_bb.tld testcmd_c01-bb.tld

testcmd-%:
	@$(O-O-TRACE.target)
	-cd $(TEST.dir) && $(EXE.pl) $(TEST.init) $(TEST.args) $(shell echo "$*" | awk -F_ '{print $$NF}')
# TODO: need verbose for executed command
# TODO: should add --no-dns if hostname is an IP

# = testarg-%.log and testcmd-%.log =
# Target should create a new logfile, then compare it with the current one. If
# diff  returns nothing, delete newly created logfile,  otherwise rename newly
# created logfile to name which contains the current date.
# If current logfile is/was missing, use newly created one.
# diff's STDERR is discarded (may return: "file does not exist").
# The target's command output is piped to  $(EXE.log-filter),  which is cat by
# default. This filter can be redefined as needed.  SEE Make:OSAFT_MAKE
# NOTE: all target commands are prefixed with -  this avoids that make reports
# errors if the command fails (as failture is intended, somehow).
# NOTE: testcmd-%.log  called from within t/ may return:  is up to date.
# Due to GNU Make limitations,  the more specific pattern rules  testarg-%.log
# and  testcmd-%.log  are used instead of a simple  test%.log even the targets
# are identical, except the used filter variable.
testarg-%.log:  EXE.log-filter  = $(EXE.log-filterarg)
testcmd-%.log:  EXE.log-filter  = $(EXE.log-filtercmd)

testarg-%.log: $(TEST.logdir) _FORCE
	@$(O-TRACE.target)
	@$(O-TRACE.target.log)
	@$(eval _target  := $(basename     $@) )   # remove .log in name
	@$(eval _OLD.log := $(TEST.logdir)/$@)
	@$(eval _NEW.log := $(TEST.logdir)/$@-$(TEST.today))
	@$(call EXE.log-make_or_print,$(_target),EXE.log-filter) > $(_NEW.log)
	@-test -f $(_OLD.log)  || cp $(_NEW.log) $(_OLD.log)
	@-diff    $(_OLD.log) $(_NEW.log) 2>/dev/null  && rm $(_NEW.log)
	@-ls   -l $(_OLD.log)*

testcmd-%.log: $(TEST.logdir) _FORCE
	@$(O-TRACE.target)
	@$(O-TRACE.target.log)
	@$(eval _target  := $(basename     $@) )   # remove .log in name
	@$(eval _OLD.log := $(TEST.logdir)/$@)
	@$(eval _NEW.log := $(TEST.logdir)/$@-$(TEST.today))
	@$(call EXE.log-make_or_print,$(_target),EXE.log-filter) > $(_NEW.log)
	@-test -f $(_OLD.log)  || cp $(_NEW.log) $(_OLD.log)
	@-diff    $(_OLD.log) $(_NEW.log) 2>/dev/null  && rm $(_NEW.log)
	@-ls   -l $(_OLD.log)*

# The pattern rule  testcmd-%  executes an individual target, for example:
# testcmd-c001_localhost . The following pattern executes all matching targets
# at once. The grouping is done by the rule's pattern. The pattern is searched
# for in  $(ALL.tests) .
# TODO: more documentation ...
# TODO: Examples:
#       test.pattern-info
#       test.pattern-+info
#       test.pattern-+check
#       test.pattern-+cipher
#       test.pattern-+ciphers
#       test.pattern--header
#
dbx-test.pattern-%:
	@$(O-TRACE.target)
	@$(eval _targets = $(shell echo "$(ALL.tests)" | $(EXE.wordperline) | awk '/$*/{print $$0;}'))
	@echo "# $(_targets) #"
test.pattern-%:
	@$(O-TRACE.target)
	@$(eval _targets = $(shell echo "$(ALL.tests)" | $(EXE.wordperline) | awk '/$*/{print $$0;}'))
	@-test -n "$(_targets)" \
	    && $(MAKE) $(MFLAGS) -s $(_targets) \
	    || echo "# pattern '$*' does not match any target"

# TODO: logging not yet tested (01/2019)
test.pattern-%.log:
	@$(O-TRACE.target)
	@$(O-TRACE.target.log)
	@$(eval _targets = $(shell echo "$(ALL.tests)" | $(EXE.wordperline) | awk '/$*/{print $$0".log";}'))
	@-test -n "$(_targets)" \
	    && $(MAKE) $(MFLAGS) -s $(_targets) \
	    || echo "# pattern '$*' does not match any target"


# some alias targets (humans tend to be lazy:)
# FIXME: following buggy; ends with command:  rm test.pattern-%
test.pat-%:  test.pattern-%
	@echo -n ""
test.patt-%: test.pattern-%
	@echo -n ""
#_____________________________________________________________________________
#__________________________________________________ include testing targets __|

# includes are done explicitly instead of:
#  include t/Makefile.*
# to avoid multiple inlcudes of the same file, which would result in make
# errors complaining about target redefinitions
# for a detailed description see t/Makefile.template

ifeq (,$(O-SID.gen))
    -include t/Makefile.gen
endif

ifeq (,$(O-SID.help))
    -include t/Makefile.help
endif

ifeq (,$(O-SID.warnings))
    -include t/Makefile.warnings
endif

ifeq (,$(O-SID.cipher))
    -include t/Makefile.cipher
endif

ifeq (,$(O-SID.cmd))
    -include t/Makefile.cmd
endif

ifeq (,$(O-SID.exit))
    -include t/Makefile.exit
endif

ifeq (,$(O-SID.opt))
    -include t/Makefile.opt
endif

ifeq (,$(O-SID.ext))
    -include t/Makefile.ext
endif

ifeq (,$(O-SID.hlp))
    -include t/Makefile.hlp
endif

ifeq (,$(O-SID.cgi))
    -include t/Makefile.cgi
endif

ifeq (,$(O-SID.tcl))
    -include t/Makefile.tcl
endif

ifeq (,$(O-SID.etc))
    -include t/Makefile.etc
endif

ifeq (,$(O-SID.dev))
    -include t/Makefile.dev
endif

ifeq (,$(O-SID.mod))
    -include t/Makefile.mod
endif

ifeq (,$(O-SID.init))
    -include t/Makefile.init
endif

ifeq (,$(O-SID.inst))
    -include t/Makefile.inst
endif

ifeq (,$(O-SID.misc))
    -include t/Makefile.misc
endif

ifeq (,$(O-SID.critic))
    -include t/Makefile.critic
endif

ifeq (,$(O-SID.docker))
    -include t/Makefile.docker
endif

ifeq (,$(O-SID.legacy))
    -include t/Makefile.legacy
endif

ifeq (,$(O-SID.make))
    -include t/Makefile.make
endif

#_____________________________________________________________________________
#_____________________________________________________________________ test __|

HELP-_test      = ______________________________________ targets for testing _
HELP-tests      = make all tests
HELP-test       = alias for tests
HELP-tests.log  = same as tests but store results in '$(TEST.logdir)/'
HELP-tests.quick    = like tests, but less targets (for development)
HELP-tests.quick.log  = like tests.log, but less targets (for development)
HELP-help.test.all  = print available individual targets for testing
HELP-test.log.ls    = list files in '$(TEST.logdir)/' generated by test.log
HELP-test.%.log.ls  = list files in '$(TEST.logdir)/' generated by test.EXT.log
HELP-test.log.ls.today  = list files in '$(TEST.logdir)/' with suffix '$(TEST.today)'
HELP-test.pattern-% = only execute targets matching '%'

tests: O-TRACE.target = echo "\\012\#\# $@: $(EXE.pl) $(TEST.args)"
tests:      $(ALL.tests)
	@$(O-TRACE.target)
	@$(MAKE) $(MFLAGS) -s $(ALL.tests)

tests.log:  $(ALL.tests.log)
	@$(O-TRACE.target)
	@$(MAKE) $(MFLAGS) -s $(ALL.tests.log)
	@-$(EXE.log-compare-hint)
	@-$(EXE.log-move-hint)

test.tests.log-compare: TEST.target_prefix  = test
test.tests.log-move:    TEST.target_prefix  = test
test.tests.log:         TEST.target_prefix  = test
test.log-compare:       TEST.target_prefix  = test
test.log-move:          TEST.target_prefix  = test

# quick tests for development
# the target is named tests.quick instead of test.quick to avoid future naming
# conflicts (if there is a Makefile.quick);
# unfortunately the targets test*s.quick.log*  must then be explicitly defined
# because the pattern rules  test.%.log* do not match
tests.quick:
	@$(MAKE) $(MFLAGS) -s tests     ALL.test.ext= ALL.test.misc= ALL.test.critic=
#tests.quick.log:
#	@$(MAKE) $(MFLAGS) -s tests.log ALL.test.ext= ALL.test.misc ALL.test.critic=
# FIXME: tests.quick.log not yet working; need to use variable in each Makefile.*
tests.quick.log:
	@$(O-TRACE.target)
	@$(O-TRACE.target.log)
	$(MAKE) $(MFLAGS) -s tests.log ALL.tests.log="test.warnings.log test.cmd.log test.exit.log test.opt.log test.cgi.log test.tcl.log"
	@-$(EXE.log-compare-hint)

tests.quick.log-compare:
	@$(O-TRACE.target)
	@-$(EXE.log-compare)
	@-$(EXE.log-move-hint)
	@echo "# 12 logfiles with differences could be expected."

tests.quick.log-move:
	@$(O-TRACE.target)
	$(EXE.log-move)

# aliases for convenience
test:       tests
test.log:   tests.log
	@$(O-TRACE.target)
	@echo "# to show differences with $(EXE.diff), use:"
	@echo "    $(MAKE_COMMAND) $@-compare"

test.log.ls:
	@$(O-TRACE.target)
	@-ls $(TEST.logdir)/test*.log

test.%.log.ls:
	@$(O-TRACE.target)
	@-ls -l $(TEST.logdir)/test*-$(*)*.log

test.log.ls.today:
	@$(O-TRACE.target)
	@-ls $(TEST.logdir)/test*.log-$(TEST.today)


# collect targets in this file, should not be added to ALL.tests
ALL.test.self  += tests tests.quick tests.log tests.quick.log

.PHONY: test tests test.log tests.log

#_____________________________________________________________________________
#________________________________________ targets for checking test results __|

HELP-_compare   = _________ targets to compare and rename generated logfiles _
HELP-test.log-compare   = compare logfiles of previous with latest test
HELP-test.log-move      = rename logfiles of latest test
HELP-help.test.log-info = print more details about test.log.* targets

HELP.test.log-info      = $(O-NL)\
\#                      $(HELP-_compare)$(O-NL)\
test.log-compare    \# static rule to compare logfiles$(O-NL)\
test.log-move       \# static rule to rename (move) latest logfiles to "standard" logfile$(O-NL)\
test.%.log-compare  \# pattern rule for test.log-compare$(O-NL)\
test.%.log-move     \# pattern rule for test.log-move$(O-NL)\
$(O-NL)\
\#$(O-NL)\
\# all above targets can be controlled with environment variables:$(O-NL)\
\#   TEST.logdir        - directory where to find logfiles$(O-NL)\
\#   TEST.target_prefix - prefix of targets to search logfiles for (files to be matched)$(O-NL)\
\#   TEST.log-suffix    - suffix of logfiles to be compared to "standard" logfile$(O-NL)\
\#   EXE.log-diff       - program used to show difference of latest and "standard" logfile$(O-NL)\
\# defaults:$(O-NL)\
\#   TEST.logdir        = $(TEST.logdir)$(O-NL)\
\#   TEST.target_prefix = $(TEST.target_prefix)$(O-NL)\
\#   TEST.log-suffix    = $(TEST.log-suffix)$(O-NL)\
\#   EXE.log-diff       = $(EXE.log-diff)$(O-NL)\
\# test example with adapted environment variables:$(O-NL)\
\#   $(MAKE_COMMAND) $@  TEST.logdir=/tmp TEST.log-suffix=-0815$(O-NL)\
\#$(O-NL)\
\# to see what the targets actually do, use$(O-NL)\
\# (environment variables may be added as needed, see above):$(O-NL)\
\#   $(MAKE_COMMAND) -n test.log-compare$(O-NL)\
\#   $(MAKE_COMMAND) -n test.log-move$(O-NL)\

help.test.log-info:
	@echo "$(HELP.test.log-info)"

# summary variables (mainly used for INSTALL.sh)
_ALL.devtools.extern   += $(EXE.diffs)

# default prefix, may be redifined per target
TEST.target_prefix  = testcmd-
TEST.target_logfile = $(TEST.logdir)/testcmd-

# default suffix for logfiles
TEST.log-suffix     = -$(TEST.today)

test.log-compare-hint:
	@-$(EXE.log-compare-hint)

test.%.log-compare:
	@$(O-TRACE.target)
	@-$(EXE.log-compare)
	@-$(EXE.log-move-hint)

test.%.log-move:
	@$(O-TRACE.target)
	$(EXE.log-move)

test.log-compare:
	@$(O-TRACE.target)
	@-$(EXE.log-compare)
	@-$(EXE.log-move-hint)

test.log-move:
	@$(O-TRACE.target)
	$(EXE.log-move)

#_____________________________________________________________________________
#________________________________________________ collected ALL.* variables __|

ALL.tests      :=
ALL.tests.log  :=

# add all tests from included files to ALL.tests += ALL.test.$INCLUDE
ifndef ALL-macros-generated
    $(foreach inc, $(ALL.inc.type), $(eval  ALL.tests      += $(ALL.test.$(inc))) )
    $(foreach inc, $(ALL.inc.type), $(eval  ALL.tests.log  += $(ALL.test.$(inc).log)) )
endif

# satisfy generated variables
ALL.test.test      := $(ALL.tests)
ALL.test.test.log  := $(ALL.tests.log)
