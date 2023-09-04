#! /usr/bin/make -rRf
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
#       _SID.myTYPE     - version number
#       _MYSELF.myTYPE  - name of current file
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
#?      @(#) Makefile 1.149 23/09/04 14:51:39
#?
#? AUTHOR
#?      18-apr-18 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

HELP-help.test.test = general testing targets

_SID.test          := 1.149

_MYSELF.test       := t/Makefile
ALL.includes       += $(_MYSELF.test)
ALL.inc.type       += test
ALL.help.tests     += help.test

export OSAFT_MAKE  := avoid writing random data (like date and time string)
export LANG        := C
export LC_CTYPE    := C.UTF-8
    # LANG ensures same messages and sorting everywhere  
    # LC_CTYPE should ensures that all characters are proper encoded

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
    $(eval _keep = OSAFT_MAKE   LANG    LC_CTYPE \
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
TEST.logdir     = $(TEST.dir)/log
TEST.logtxt    := <<random value replaced by make>>
TEST.symlinks  := ../contrib ../osaft.pm ../.o-saft.pl ../Net ../docs ../OSaft

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

ifndef SRC.contrib.dir
    SRC.contrib.dir = contrib
endif

# Tracing just the log-targets is special. Using  $(TRACE.target)  is not an
# option, because it would als change the final target called with  $(MAKE) .
# Hence an additional variable is used.
# TODO: not public, not documented, variable needs to be defined here
TRACE.target.log    =
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

# TRACE.target is not empty if target was  test*-compare-v or test*-move-v . So
# it is sufficent to check TRACE.target. If it's not empty, verbose information
# will be printed.
# TODO: not tested if following defines could be written as macros
# SEE Make:defines with commands

define EXE.log-compare
	cd $(TEST.logdir) && \
	echo "# compare "`ls $(TEST.target_prefix)*.log$(TEST.log-suffix) | wc -l`" file ..." && \
	for f in $(TEST.target_prefix)*.log; do \
	    [ -f $${f}$(TEST.log-suffix) ] || continue ; \
	    [ -n '$(TRACE.target)' ] && echo "# $(TEST.logdir)/$${f} ..." ; \
	    $(EXE.log-diff) $${f} $${f}$(TEST.log-suffix) >/dev/null 2>&1 ; \
	done
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
	    [ -n '$(TRACE.target)' ] && echo "# $(TEST.logdir)/$${f} ..." ; \
	    mv $${f}$(TEST.log-suffix) $${f} ; \
	done
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


HELP.test       = $(_NL)\
\# The term '%'  in the targets names described here, may be any of:$(_NL)\
\#   $(ALL.inc.type)$(_NL)\
\#$(_NL)\
\# Following variables are intended to be used on command line:$(_NL)\
\#   EXE.pl      - program to perform tests, default: '$(EXE.pl)'$(_NL)\
\#   TEST.init   - arguments and options always passed to EXE.pl; default: '$(TEST.init)'$(_NL)\
\#   TEST.args   - arguments and options to be  passed to EXE.pl per target$(_NL)\
\#   TEST.host   - hostname to be used for tests (when only one is expected)$(_NL)\
\#   TEST.hosts  - list of hostnames to perform tests with$(_NL)\
\#   TEST.dir    - directory in which EXE.pl will be executed; default: '$(TEST.dir)/'$(_NL)\
\#   TEST.logdir - directory where results of EXE.pl will be stored; default: '$(TEST.logdir)/'$(_NL)\
\#   TEST.rc     - content of RC-file to be used by EXE.pl: '$(TEST.rc)'$(_NL)\
\#   TEST.target_prefix - prefix of log-filename; see help.test.log-info$(_NL)\
\#   TEST.log-suffix    - suffix of log-filename; see help.test.log-info$(_NL)\
\#$(_NL)\
\# Notes about some spezial targets:$(_NL)\
\#   help.test   - automatically generated target; alias for help.test.test$(_NL)\
\#   help.test.test.alls -$(_NL)\
\#   help.test.test.all - be prepared for huge output$(_NL)\
\#$(_NL)\
\# Keep in mind that following files are located in '$(TEST.dir)/':$(_NL)\
\#   .o-saft.pl  $(TEST.rc)  .o-saft.tcl$(_NL)\
\# which are used by EXE.pl or other tools used for the tests.

# following variable contains (huge) list of all available targets
HELP.test.test.all  = $(_NL)\
\# $(words $(ALL.tests)) targets for tests:$(_NL)\
$(ALL.tests)$(_NL)\
\#$(_NL)\
\# $(words $(ALL.tests.log)) targets which write results to logfiles:$(_NL)\
$(ALL.tests.log)$(_NL)\
\#$(_NL)\
\# summary targets for tests:$(_NL)\
$(ALL.help.tests:help.%=%)$(_NL)\
\#$(_NL)\
\# for more target and details, following targets can be used$(_NL)\
$(foreach target,$(ALL.inc.type),t-$(target))$(_NL)

HELP.test.test  = $(HELP.test)
HELP.test.all   = $(HELP.test.test.all)
help.test:          help.test.test
help.test.all:      help.test.test.all
	@$(TRACE.target)
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

# experimental: some targets print too many shell commands
help.test.test.all-n:
	@$(TRACE.target)
	@$(MAKE) -n $(ALL.tests)

help.test.test.alls:
	@$(TRACE.target)
	@echo " # $(words $(ALL.tests)) targets for tests:"
	@echo $(ALL.tests) | $(EXE.wordperline) | sort $(_EXE.sort-opt)
	@echo ""

help.test.%.all:
	@$(TRACE.target)
	@echo " # individual targets for testing $* :"
	@echo $(ALL.test.$*) | $(EXE.wordperline) | sort $(_EXE.sort-opt)
	@echo ""
	@echo "$(HELP.test.$*.all)"

HELP-help.test.%.internal   = show settings for tests '%' from Makefile.*
help.test.%.internal:
	@$(TRACE.target)
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
	@$(MAKE) -s $(ALL.help.tests.all $(ALL.help.test.internal)

#_____________________________________________________________________________
#_____________________________________________________ internal test target __|

HELP-_internal  = _____________________________________ internal test target _
HELP-testcmd-test.internal = print GNU Make's internals and global project settings
# dummy ' to keep some stupid syntax highlighting happy

# internal information (nothing related to $(O-Project))
# NOTE: $(_SID*) variables indicate if a t/Makefile* was included.
# NOTE: $$  needs to be used to ensure that the variables are evaluated when
#       the target executes and not when the Makefile is read.
# NOTE: when target testcmd-test.internal is called with  -n ; the command:
#           @echo '# $$(MAKE)          = $(MAKE)'
#       will produce output:
#           # $(MAKE)          = make
#       SEE GNU Make:MAKE vs. MAKE_COMMAND
# TODO: list of $(_SID.*) should be generated using $(ALL.inc.type)
test.file-1:
test,file-2:
test_file-3:
testcmd-test.internal: test.file-1 test,file-2 test_file-3
	@$(TRACE.target)
	@echo 'test.target: test.file-1 test-file-2 test_file-3'
	@echo '# SIDs of included Makefile* (file not included if SID missing):'
	@echo '# $$(_SID)          = $(_SID)'
	@echo '# $$(_SID.help)     = $(_SID.help)'
	@echo '# $$(_SID.test)     = $(_SID.test)'
	@echo '# $$(_SID.critic)   = $(_SID.critic)'
	@echo '# $$(_SID.warnings) = $(_SID.warnings)'
	@echo '# $$(_SID.cipher)   = $(_SID.cipher)'
	@echo '# $$(_SID.make)     = $(_SID.make)'
	@echo '# $$(_SID.exit)     = $(_SID.exit)'
	@echo '# $$(_SID.init)     = $(_SID.init)'
	@echo '# $$(_SID.misc)     = $(_SID.misc)'
	@echo '# $$(_SID.cmd)      = $(_SID.cmd)'
	@echo '# $$(_SID.dev)      = $(_SID.dev)'
	@echo '# $$(_SID.mod)      = $(_SID.mod)'
	@echo '# $$(_SID.etc)      = $(_SID.etc)'
	@echo '# $$(_SID.ext)      = $(_SID.ext)'
	@echo '# $$(_SID.cgi)      = $(_SID.cgi)'
	@echo '# $$(_SID.gen)      = $(_SID.gen)'
	@echo '# $$(_SID.hlp)      = $(_SID.hlp)'
	@echo '# $$(_SID.inc)      = $(_SID.inc)'
	@echo '# $$(_SID.opt)      = $(_SID.opt)'
	@echo '# $$(_SID.pod)      = $(_SID.pod)'
	@echo '# $$(_SID.tcl)      = $(_SID.tcl)'
	@echo '# $$(_SID.docker)   = $(_SID.docker)'
	@echo '# $$(_SID.legacy)   = $(_SID.legacy)'
	@echo '# $$(_SID.template) = $(_SID.template)'
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
	@echo '# $$(MFLAGS)        = $(MFLAGS)'
	@echo '# $$(MAKEFLAGS)     = $(MAKEFLAGS)'
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
	@echo '# $$(.INCLUDE_DIRS) = $(.INCLUDE_DIRS)'
	@echo '# $$(.INTERMEDIATE) = $(.INTERMEDIATE)'
	@echo '# $$(.PRECIOUS)     = $(.PRECIOUS)'
	@echo '# $$(.RECIPEPREFIX) = $(.RECIPEPREFIX)'
	@echo '# $$(.SECONDARY)    = $(.SECONDARY)'
	@echo '# $$(.SHELLFLAGS)   = $(.SHELLFLAGS)'
	@echo '# $$(.SUFFIXES)     = $(.SUFFIXES)'
	@echo '# $$(.FEATURES)     = $(.FEATURES)'
	@echo '# $$(.VARIABLES)    = $(words $(.VARIABLES)) variables'
	@echo '#                    huge list .VARIABLES not shown (includes own names),'
	@echo '#                    use: make help.test.makevars'
# not printed because different for each call: $(MAKE_TERMOUT) $(MAKE_TERMERR)
# not used as most likely not a variable: .DEFAULT  .PHONY  .SECONDEXPANSION

# TODO (2022) not yet added to proper variables
ALL.help.test      += testcmd-test.internal
ALL.tests          += testcmd-test.internal

help.test.makevars:
	@echo '# $$(.VARIABLES)    = '
	@echo '$(.VARIABLES)' | $(EXE.wordperline) | sort $(_EXE.sort-opt)

.PHONY: help.test.makevars

#_____________________________________________________________________________
#______________________________________________________ targets for testing __|

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
	@$(TRACE.target)
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


# Testing for messages or other strings (i.e **WARNING) works as follows:
#   call $(EXE.pl) with command and/or options in question
#   then search (grep) output for message (string)
# For some behaviours of $(EXE.pl) a RC-file is required.
# Different target rules can be mapped to the pattern rule message-%. It gets
# the message string  from the automatic variable  $* , and all arguments for
# $(EXE.pl) with following Makefile variables:
#   $(TEST.init)    - command, options to be passed to $(EXE.pl)
#   $(TEST.args)    - command, options and hostname to be passed to $(EXE.pl)
#   $(TEST.rc)      - content of RC-file to be used by $(EXE.pl)
# These variables can be set conditinally for each target, see example below.
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
# NOTE: even  TEST.tmp.rc  is generated  for each call,  it will only be used
# when requested with the  --rc=some.rc  option.
#
# NOTE: if  TEST.args  contains special characters,  syntax errors may occour
# when used in the shell. Quoting  TEST.args  is not possible because then it
# becomes a single argument instead of discrete arguments. At least following
# special characters should not be used:  ; & | # < > ` [ ]
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

_FORCE:

# target succeeds if message is there
message-%:
	@$(TRACE.target)
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
	@$(TRACE.target)
	@echo "$(TEST.rc)" > $(TEST.tmp.rc)
	cd $(TEST.dir) && $(EXE.pl) $(TEST.init) $(TEST.args) 2>&1 | awk '/ $*/{exit 1}'
	@rm -f $(TEST.tmp.rc)

# Simple target to calL: $(EXE.pl) $(TEST.init) $(TEST.args)
testarg-%:
	@$(TRACE.target)
	-cd $(TEST.dir) && $(EXE.pl) $(TEST.init) $(TEST.args)

# SEE Make:--dry-run
# following pattern rule should be unified with testcmd-%.log
testarg-%.log: $(TEST.logdir) _FORCE
	@$(TRACE.target)
	@$(TRACE.target.log)
	@$(eval _NEW.log := $(TEST.logdir)/$@-$(TEST.today))
	@expr "$(MAKEFLAGS)" : n >/dev/null \
	    && echo "$(MAKE) $(MFLAGS) -s testarg-$* 2>&1 | $(EXE.log-filterarg) > $@ 2>&1" \
	    ||       $(MAKE) $(MFLAGS) -s testarg-$* 2>&1 | $(EXE.log-filterarg) > $@ 2>&1
	@-diff $(TEST.logdir)/$@ $@ 2>/dev/null \
	    && rm $@ \
	    || mv $@ $(_NEW.log)
	@-test -f $(TEST.logdir)/$@  ||  mv $(_NEW.log) $(TEST.logdir)/$@
	@-ls -l  $(TEST.logdir)/testarg-$(*)*
# TODO: target should fail if there is a diff


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
	@$(TRACE.target)
	-cd $(TEST.dir) && $(EXE.pl) $(shell echo "$*" | awk -F_ '{print $$NF}') $(TEST.init) $(TEST.args)
# TODO: need verbose for executed command
# TODO: need to add --no-dns if hostname is an IP

# Target should create a new logfile, then compare it with the current one. If
# diff  returns nothing, delete newly created logfile,  otherwise rename newly
# created logfile to name which contains the current date.
# Finally, if current logfile is/was missing, use newly created one:
# "test ... || mv ..." . This ensures that the file exists afterwards.
# diff's STDERR is discarded (may return: "file does not exist").
# The target's command output is piped to  $(EXE.log-filtercmd),  which is cat
# by default. This filter can be redefined as needed.  SEE Make:OSAFT_MAKE
# NOTE: all target commands are prefixed with -  this avoids that make reports
# errors if the command fails (as failture is intended, somehow).
# NOTE: testcmd-%.log  called from within t/ may return:  is up to date.

testcmd-%.log: $(TEST.logdir) _FORCE
	@$(TRACE.target)
	@$(TRACE.target.log)
	@$(eval _NEW.log := $(TEST.logdir)/$@-$(TEST.today))
	@expr "$(MAKEFLAGS)" : n >/dev/null \
	    && echo "$(MAKE) $(MFLAGS) -s testcmd-$* 2>&1 | $(EXE.log-filtercmd) > $@ 2>&1" \
	    ||       $(MAKE) $(MFLAGS) -s testcmd-$* 2>&1 | $(EXE.log-filtercmd) > $@ 2>&1
	@-diff $(TEST.logdir)/$@ $@  >/dev/null 2>&1 || echo "diff $(TEST.logdir)/$@ ..."
	@-diff $(TEST.logdir)/$@ $@ 2>/dev/null \
	    && rm $@ \
	    || mv $@ $(_NEW.log)
	@-test -f $(TEST.logdir)/$@  ||  mv $(_NEW.log) $(TEST.logdir)/$@
	@-ls -l  $(TEST.logdir)/testcmd-$(*)*
# TODO: target should fail if there is a diff


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
	@$(TRACE.target)
	@$(eval _targets = $(shell echo "$(ALL.tests)" | $(EXE.wordperline) | awk '/$*/{print $$0;}'))
	@echo "# $(_targets) #"
test.pattern-%:
	@$(TRACE.target)
	@$(eval _targets = $(shell echo "$(ALL.tests)" | $(EXE.wordperline) | awk '/$*/{print $$0;}'))
	@-test -n "$(_targets)" \
	    && $(MAKE) $(MFLAGS) -s $(_targets) \
	    || echo "# pattern '$*' does not match any target"

# TODO: logging not yet tested (01/2019)
test.pattern-%.log:
	@$(TRACE.target)
	@$(TRACE.target.log)
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

ifeq (,$(_SID.gen))
    -include t/Makefile.gen
endif

ifeq (,$(_SID.help))
    -include t/Makefile.help
endif

ifeq (,$(_SID.warnings))
    -include t/Makefile.warnings
endif

ifeq (,$(_SID.cipher))
    -include t/Makefile.cipher
endif

ifeq (,$(_SID.cmd))
    -include t/Makefile.cmd
endif

ifeq (,$(_SID.exit))
    -include t/Makefile.exit
endif

ifeq (,$(_SID.opt))
    -include t/Makefile.opt
endif

ifeq (,$(_SID.ext))
    -include t/Makefile.ext
endif

ifeq (,$(_SID.hlp))
    -include t/Makefile.hlp
endif

ifeq (,$(_SID.cgi))
    -include t/Makefile.cgi
endif

ifeq (,$(_SID.tcl))
    -include t/Makefile.tcl
endif

ifeq (,$(_SID.etc))
    -include t/Makefile.etc
endif

ifeq (,$(_SID.dev))
    -include t/Makefile.dev
endif

ifeq (,$(_SID.mod))
    -include t/Makefile.mod
endif

ifeq (,$(_SID.init))
    -include t/Makefile.init
endif

ifeq (,$(_SID.misc))
    -include t/Makefile.misc
endif

ifeq (,$(_SID.critic))
    -include t/Makefile.critic
endif

ifeq (,$(_SID.docker))
    -include t/Makefile.docker
endif

ifeq (,$(_SID.legacy))
    -include t/Makefile.legacy
endif

ifeq (,$(_SID.make))
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
HELP-test.pattern-% = only execute targets matching '%'

tests: TRACE.target = echo "\\012\#\# $@: $(EXE.pl) $(TEST.args)"
tests:      $(ALL.tests)
	@$(TRACE.target)
	@$(MAKE) $(MFLAGS) -s $(ALL.tests)

tests.log:  $(ALL.tests.log)
	@$(TRACE.target)
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
	@$(TRACE.target)
	@$(TRACE.target.log)
	$(MAKE) $(MFLAGS) -s tests.log ALL.tests.log="test.warnings.log test.cmd.log test.exit.log test.opt.log test.cgi.log test.tcl.log"
	@-$(EXE.log-compare-hint)

tests.quick.log-compare:
	@$(TRACE.target)
	@-$(EXE.log-compare)
	@-$(EXE.log-move-hint)
	@echo "# 12 logfiles with differences could be expected."

tests.quick.log-move:
	@$(TRACE.target)
	$(EXE.log-move)

# aliases for convenience
test:       tests
test.log:   tests.log
	@$(TRACE.target)
	@echo "# to show differences with $(EXE.diff), use:"
	@echo "    $(MAKE_COMMAND) $@-compare"

test.log.ls:
	@$(TRACE.target)
	@-ls $(TEST.logdir)/test.*log

test.%.log.ls:
	@$(TRACE.target)
	@-ls -l $(TEST.logdir)/test*-$(*)*log


# collect targets in this file, should not be added to ALL.tests
ALL.test.self  += tests tests.quick tests.log tests.quick.log

.PHONY: test tests test.log tests.log

#_____________________________________________________________________________
#________________________________________ targets for checking test results __|

HELP-_compare   = _________ targets to compare and rename generated logfiles _
HELP-test.log-compare   = compare logfiles of previous with latest test
HELP-test.log-move      = rename logfiles of latest test
HELP-help.test.log-info = print more details about test.log.* targets

HELP.test.log-info      = $(_NL)\
\#                      $(HELP-_compare)$(_NL)\
test.log-compare    \# static rule to compare logfiles$(_NL)\
test.log-move       \# static rule to rename (move) latest logfiles to "standard" logfile$(_NL)\
test.%.log-compare  \# pattern rule for test.log-compare$(_NL)\
test.%.log-move     \# pattern rule for test.log-move$(_NL)\
$(_NL)\
\#$(_NL)\
\# all above targets can be controlled with environment variables:$(_NL)\
\#   TEST.logdir        - directory where to find logfiles$(_NL)\
\#   TEST.target_prefix - prefix of targets to search logfiles for (files to be matched)$(_NL)\
\#   TEST.log-suffix    - suffix of logfiles to be compared to "standard" logfile$(_NL)\
\#   EXE.log-diff       - program used to show difference of latest and "standard" logfile$(_NL)\
\# defaults:$(_NL)\
\#   TEST.logdir        = $(TEST.logdir)$(_NL)\
\#   TEST.target_prefix = $(TEST.target_prefix)$(_NL)\
\#   TEST.log-suffix    = $(TEST.log-suffix)$(_NL)\
\#   EXE.log-diff       = $(EXE.log-diff)$(_NL)\
\# test example with adapted environment variables:$(_NL)\
\#   $(MAKE_COMMAND) $@  TEST.logdir=/tmp TEST.log-suffix=-0815$(_NL)\
\#$(_NL)\
\# to see what the targets actually do, use$(_NL)\
\# (environment variables may be added as needed, see above):$(_NL)\
\#   $(MAKE_COMMAND) -n test.log-compare$(_NL)\
\#   $(MAKE_COMMAND) -n test.log-move$(_NL)\

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
	@$(TRACE.target)
	@-$(EXE.log-compare)
	@-$(EXE.log-move-hint)

test.%.log-move:
	@$(TRACE.target)
	$(EXE.log-move)

test.log-compare:
	@$(TRACE.target)
	@-$(EXE.log-compare)
	@-$(EXE.log-move-hint)

test.log-move:
	@$(TRACE.target)
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
