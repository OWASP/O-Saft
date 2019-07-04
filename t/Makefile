#! /usr/bin/make -rRf
#?
#? NAME
#?      Makefile        - makefile for testing O-Saft
#?
#? SYNOPSYS
#?      make [options] [target] [...]
#?
#? DESCRIPTION
#?      Makefile containing general testing targets for O-Saft project.
#?
#? LIMITATIONS
#?      Requires GNU Make > 2.0.
#?
# HACKER's INFO
#       For details please see
#           ../Makefile  Makefile.help  Makefile.template
#
#    Naming conventions for t/Makefile*
#       * macro names have the prefix  TEST.
#       * target names for public use have the prefix  test.
#       * individual, special targets have the prefix  _test (exceptions exist)
#
#    Special variables specific for each t/Makefile*
#       _SID.TYPE       - version number
#       _MYSELF.TYPE    - name of current file
#       _MY.includes    - list of Makefiles
#       _MY.inc.type    - type of tests (should be suffix of Makefile's name)
#       ALL.help.test   - list of documentation (help) texts
#       HELP.TYPE       - documentation (help) text for the corresponding file
#       HELP.TYPE.all   - list of all targets for the corresponding file
#       HELP.TYPE.internal  - some more documentation (help) text
#           where  TYPE  is the suffix of the Makefile's filename
#
#    Each t/Makefile* may also redefine following variables
#       HELP_TYPE       - suffix (and type) of Makefile*
#       HELP_HEAD       - descriptive header line, set to HELP_NAME, HELP_RULE 
#
#    Special targets for documentation (help) in t/Makefile*
#       help.test.%     - print individual documentation using $(HELP.TYPE)
#       help.test.%.all - print all targets using $(HELP.TYPE.all)
#       help.test.%.internal - print details using $(HELP.TYPE.internal)
#           where  %  is the suffix of the Makefile's filename
#
#       TODO:
#          * include Makefile.* should be generic
#          * unify test.warnings.log and test.tests.log (should use same target)
#          * rename ALL.tests and ALL.tests.log (too similar to ALL.test)
#
#? VERSION
#?      @(#) Makefile 1.63 19/07/04 08:15:16
#?
#? AUTHOR
#?      18-apr-18 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

_SID.test       = 1.63

_MYSELF.test    = t/Makefile
_MY.includes   += $(_MYSELF.test)
_MY.inc.type   += test
                # this is the parent makefile in the directory

first-test-target-is-default: help.test

ALL.help.test  += help.test

HELP-help.test.test = general testing targets
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

ifndef ALL.Makefiles
    -include t/Makefile.inc
    # defines macros if called directly (not from ../Makefile)
endif

ALL.inc.type   += $(_MY.inc.type)
# NOTE: this adds all $(_MY.inc.type) from all Makefile.* automatically
#       as a result, $(ALL.inc.type) contains all types of all included files

#_____________________________________________________________________________
#________________________________________________________________ variables __|

# store -n (dry-run) option in own variable
_n := $(if $(findstring n,$(firstword -$(MAKEFLAGS))),-n)

# test tools (part of distribution)
TEST.dir        = t
TEST.logdir     = $(TEST.dir)/log

# following may be redefined in included t/Makefiles*
# TEST.init       = --header
# TEST.args       =

# macro for list of hostnames needs to be unique in each Makefile*
# otherwise some targets in other Makefile* get confused
#TEST.host       = localhost
#TEST.hosts      =

# following defined in ../Makefile
# TEST.do  =
# SRC.test =
# ALL.test =

# defined in other t/Makefile*
# ALL.tests =

#  $(SRC.rc)  may not be defined here, hence hardcoded

OPT.grep        = -q
    # grep (mainly used in message-% target) should not report matching lines
    # macro can be reset or redifined for more verbose output

ifndef CONTRIB.dir
    CONTRIB.dir = contrib
endif

# Tracing just the log-targets is special. Using  $(TRACE.target)  is not an
# option, because it would als change the final target called with  $(MAKE) .
# Hence an additional variable is used.
# TODO: not public, not documented, variable needs to be defined here
TRACE.target.log=
    #  example  = echo "\# $*\tcalling: $(MAKE) -s testcmd-$*"

_TODAY_         = $(shell date +%Y""%m%d)
    # current date in ISO format

# define script or parts of it as variables, for better human readability
# SEE Make:target matching
#     _AWK_macro_by_line    - extract all macro  names
#     _AWK_target_by_line   - extract all target names
#     _AWK_target_to_arr    - extract target names and store uniquely in arr[]
#     _AWK_print_arr_END    - print collected data from arr[]
#     _AWK_print_file       - either print separator line or the filename
TEST.target_prefix  =   [a-zA-Z][_a-zA-Z.]
   # matching target names not starting with _
_AWK_macro_by_line  = /^[a-zA-Z_][a-zA-Z_.]* *=/{sub(/=/,"",$$1);print $$1}
_AWK_target_by_line = /^[a-zA-Z_][a-zA-Z_.]* *:/{sub(/:/,"",$$1);print $$1}
_AWK_target_to_arr  = /^.*%/{next} /^$(TEST.target_prefix)*/{arr[$$1]=1}
_AWK_print_arr_END  = END{for(idx in arr){print idx}}
_AWK_print_file     = (FNR==1){ x="";for(i=1;i<62;i++){x=sprintf("%s%c",x,"-")};print "\n\t\t\#"x}


HELP.test       = $(_NL)\
\# Following variables are intended to be used on command line:$(_NL)\
\#$(_NL)\
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
\# Keep in mind that following files are located in '$(TEST.dir)/':$(_NL)\
\#   .o-saft.pl  $(TEST.rc)  .o-saft.tcl$(_NL)\
\# which are used by EXE.pl or other tools used for the tests.

# following macro contains (huge) list of all available targets
HELP.test.test.all  = $(_NL)\
\# summary targets for tests$(_NL)\
$(ALL.tests)$(_NL)\
\#$(_NL)\
\# targets which write results to logfiles$(_NL)\
$(ALL.tests.log)$(_NL)\
\#$(_NL)\
\# for more target and details, following targets can be used$(_NL)\
$(foreach target,$(_MY.inc.type),t-$(target))$(_NL)

HELP.test.test  = $(HELP.test)
HELP.test.all   = $(HELP.test.test.all)
help.test:          help.test.test
help.test.all:      help.test.test.all
	@$(TRACE.target)
# convenience to satisfy  help.test.all

# help.test.test would only print the HELP-* texts from herein.
# All other tests from the individual t/Makefile.* files have their own HELP-*
# macro their.  help.test.test  should also print hints how to get information
# about these other targets. Therfore the auxiliary target  _help_list  exists
# in  Makefile  which we use as dependency here.
help.test.test:     _help_list
help.test.test-v:   _help_list
help.test.test-v-v: _help_list

#_____________________________________________________________________________
#____________________________________________ target for help in t/Makefile*__|

HELP-help.test.*.all        = print available individual targets for tests from Makefile.*
help.test.%.all:
	@$(TRACE.target)
	@echo " # individual targets for testing $* :"
	@echo $(ALL.test.$*)
	@echo ""
	@echo "$(HELP.test.$*.all)"

HELP-help.test.*.internal   = show settings for tests from Makefile.*
help.test.%.internal:
	@$(TRACE.target)
	@echo " # TEST.file:       $(TEST.file)"
	@echo " # TEST.init.$*:    $(TEST.init.$*)"
	@echo " # TEST.$*.hosts:   $(TEST.$*.hosts)"
	@echo " # ALL.test$*:     $(words $(ALL.test$*))  : $(ALL.test$*)"
	@echo " # ALL.test.$*:    $(words $(ALL.test.$*)) : $(ALL.test.$*)"
	@echo $(HELP.$*.internal)
	@echo " # -------------------------------------------------------------"

help-test-all       = $(foreach type,$(_MY.inc.type), help.test.$(type).all)
help-test-internal  = $(foreach type,$(_MY.inc.type), help.test.$(type).internal)
help.test.targets:
	@$(MAKE) -s $(help-test-all) $(help-test-internal)

#_____________________________________________________________________________
#_____________________________________________________ internal test target __|

HELP-_internal  = _____________________________________ internal test target _
HELP-help.test.make = print GNU Make's internals and global project settings
# dummy ' to keep some stupid syntax highlighting happy

# internal information (nothing related to $(Project))
# NOTE: $(_SID*) variables indicate if a sub-makefile was included.
# NOTE: $$  needs to be used to ensure that the variables are evaluated when
#      the targets executes and not when the Makefile is read.
test.file-1:
test,file-2:
test_file-3:
help.test.make: test.file-1 test,file-2 test_file-3
	@$(TRACE.target)
	@echo 'test.target: test.file-1 test-file-2 test_file-3'
	@echo '# SIDs of included Makefile* (file not included if SID missing):'
	@echo '# $$(_SID)          = $(_SID)'
	@echo '# $$(_SID.help)     = $(_SID.help)'
	@echo '# $$(_SID.test)     = $(_SID.test)'
	@echo '# $$(_SID.critic)   = $(_SID.critic)'
	@echo '# $$(_SID.warnings) = $(_SID.warnings)'
	@echo '# $$(_SID.exit)     = $(_SID.exit)'
	@echo '# $$(_SID.misc)     = $(_SID.misc)'
	@echo '# $$(_SID.cmds)     = $(_SID.cmds)'
	@echo '# $$(_SID.doc)      = $(_SID.doc)'
	@echo '# $$(_SID.ext)      = $(_SID.ext)'
	@echo '# $$(_SID.cgi)      = $(_SID.cgi)'
	@echo '# $$(_SID.hlp)      = $(_SID.hlp)'
	@echo '# $$(_SID.inc)      = $(_SID.inc)'
	@echo '# $$(_SID.opt)      = $(_SID.opt)'
	@echo '# $$(_SID.tcl)      = $(_SID.tcl)'
	@echo '# show some private make variables:'
	@echo '# $$(PWD)           = $(PWD)'
	@echo '# $$(PWD.dir)       = $(notdir $(PWD))'
	@echo '# $$(TEST.dir)      = $(TEST.dir)'
	@echo '# $$(TEST.logdir)   = $(TEST.logdir)'
	@echo '# $$(TEST.host)     = $(TEST.host)'
	@echo '# $$(TEST.hosts)    = $(TEST.hosts)'
	@echo '# $$(ALL.Makefiles) = $(ALL.Makefiles)'
	@echo '# $$(_MY.includes)  = $(_MY.includes)'
	@echo '# $$(_MY.inc.type)  = $(_MY.inc.type)'
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
	@echo '# $$(MAKE_TERMOUT)  = $(MAKE_TERMOUT)'
	@echo '# $$(MAKE_TERMERR)  = $(MAKE_TERMERR)'
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
	@echo '# $$(.VARIABLES)    = $(.VARIABLES)'
# not used as most likely not a variable: .DEFAULT  .PHONY  .SECONDEXPANSION

#_____________________________________________________________________________
#______________________________________________________ targets for testing __|

# FIXME: missing public (not internal) documentation for pattern rules:
#       message-%:
#       no.message-%:
#       testarg0-%:
#       testcmd-%
#       test.all-%:

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

$(TEST.logdir):
	@mkdir $@


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
# NOTE: even  _TMP.rc  is generated for each call,  it will only be used when
# requested with the  --rc=$(_TMP.rc)  option.
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

# target succeeds if message is there
message-%:
	@$(TRACE.target)
	@-if expr "$(TEST.args)" ":" "^TODO" >/dev/null ; then \
	    echo "$@:    $(TEST.args)"; \
	else \
	    echo "$(EXE.pl) $(TEST.init) $(TEST.args) 2>&1 | grep $(OPT.grep) $* " ; \
	    echo "$(TEST.rc)" > $(_TMP.rc) ; \
	    cd $(TEST.dir) && $(EXE.pl) $(TEST.init) $(TEST.args) 2>&1 | grep $(OPT.grep) $* ; \
	    _status=$$? ; \
	    rm -f $(_TMP.rc) ; \
	    exit $$_status ; \
	fi
# following removed from above, too noicy:
#            echo "echo '$(TEST.rc)' > $(_TMP.rc)" ;

# target succeeds if message is missing
# TODO: need more examples beside those in t/Makefile.cgi
no.message-%:
	@$(TRACE.target)
	@echo "$(TEST.rc)" > $(_TMP.rc)
	$(EXE.pl) $(TEST.init) $(TEST.args) 2>&1 | awk '/ $*/{exit 1}'
	@rm -f $(_TMP.rc)

# Simple target to calL: $(EXE.pl) $(TEST.init) $(TEST.args)
testarg0-%:
	@$(TRACE.target)
	-cd $(TEST.dir) && $(EXE.pl) $(TEST.init) $(TEST.args)

# SEE Make:--dry-run
# following pattern rule should be unified with testcmd-%.log
testarg0-%.log: $(TEST.logdir)
	@$(TRACE.target)
	@$(TRACE.target.log)
	@$(eval _NEW.log := $(TEST.logdir)/$@-$(_TODAY_))
	@$(MAKE) $(MFLAGS) -s testarg0-$* > $@ 2>&1
	@expr "$(MAKEFLAGS)" : n >/dev/null \
	    && echo "$(MAKE) $(MFLAGS) -s testarg0-$* > $@ 2>&1" \
	    ||       $(MAKE) $(MFLAGS) -s testarg0-$* > $@ 2>&1
	@-diff $(TEST.logdir)/$@ $@ 2>/dev/null \
	    && rm $@ \
	    || mv $@ $(_NEW.log)
	@-test -f $(TEST.logdir)/$@  ||  mv $(_NEW.log) $(TEST.logdir)/$@
	@-ls -l  $(TEST.logdir)/testarg0-$(*)*
# TODO: target should fail if there is a diff


# The goal for test targets is to perform (test) all commands with all hosts.
# The hostnames are provided in a simple list: $(TEST.hosts) .
# The commands couldn't be provided in a make macro all together, because each
# command may consist of space separated words like: "+info --header".
# Hence each command is defined in the macro  TEST.args, which will be set for
# an individual target, for example: testcmd-001 . We have one target for each
# specific test case, which actually is a list of commands and options for the
# tool $(EXE.pl) . Note that the trailing  DDD  (001 in example above) is just
# a number to make each target unique.
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
# Unfortunatelly, this pattern contains  DDD_  (for example 001_host.some.tld)
# as hostname.  This  DDD_  prefix must then be removed in the target command,
# the  $(shell awk ...)  does the dirty work. in detail (as defined below):
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
# created file to name which contains the current date.
# Finally, if current logfile is/was missing, use newly created one:
# "test ... || mv ..." . This ensures that the file exists afterwards.
# diff's STDERR is discarded (may return: "file does not exist").
# NOTE: all target commands are prefixed with -  this avoids that make reports
# errors if the command fails (as failture is intended, somehow).
# NOTE: testcmd-%.log  called from within t/ may return:  is up to date.

_FORCE:
testcmd-%.log: $(TEST.logdir) _FORCE
	@$(TRACE.target)
	@$(TRACE.target.log)
	@$(eval _NEW.log := $(TEST.logdir)/$@-$(_TODAY_))
	@expr "$(MAKEFLAGS)" : n >/dev/null \
	    && echo "$(MAKE) $(MFLAGS) -s testcmd-$* > $@ 2>&1" \
	    ||       $(MAKE) $(MFLAGS) -s testcmd-$* > $@ 2>&1
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
#       test.pattern.info
#       test.pattern.+info
#       test.pattern.+check
#       test.pattern.+cipher
#       test.pattern.+ciphers
#       test.pattern.-header
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

ifeq (,$(_SID.help))
    -include t/Makefile.help
endif

ifeq (,$(_SID.warnings))
    -include t/Makefile.warnings
endif

ifeq (,$(_SID.cmds))
    -include t/Makefile.cmds
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

ifeq (,$(_SID.doc))
    -include t/Makefile.doc
endif

ifeq (,$(_SID.misc))
    -include t/Makefile.misc
endif

ifeq (,$(_SID.critic))
    -include t/Makefile.critic
endif

#_____________________________________________________________________________
#_____________________________________________________________________ test __|

HELP-_test      = ______________________________________ targets for testing _
HELP-tests      = make all tests
HELP-test       = alias for tests
HELP-tests.log  = same as tests but store results in '$(TEST.logdir)/'
HELP-tests.quick    = like tests, but less targets (for development)
HELP-tests.quick.log= like tests.log, but less targets (for development)
HELP-help.test.all  = print available individual targets for testing

tests: TRACE.target = echo "\\012\#\# $@: $(EXE.pl) $(TEST.args)"
tests:      $(ALL.tests)
	@$(TRACE.target)

tests.log:  $(ALL.tests.log) test.log-compare-hint
	@$(TRACE.target)

test.tests.log-compare: TEST.target_prefix  = test
test.tests.log-move:    TEST.target_prefix  = test
test.tests.log:         TEST.target_prefix  = test
test.log-compare:       TEST.target_prefix  = test
test.log-move:          TEST.target_prefix  = test

# quick tests for development
tests.quick:
	@$(MAKE) $(MFLAGS) -s tests     ALL.test.ext= ALL.test.misc= ALL.test.critic=
#tests.quick.log:
#	@$(MAKE) $(MFLAGS) -s tests.log ALL.test.ext= ALL.test.misc ALL.test.critic=
# FIXME: tests.quick.log not yet working; need to use macro in each Makefile.*
tests.quick.log:
	@$(TRACE.target)
	@$(TRACE.target.log)
	$(MAKE) $(MFLAGS) -s tests.log ALL.tests.log="test.warnings.log test.cmds.log test.exit.log test.opt.log test.cgi.log test.tcl.log"

# aliases for convenience
test:       tests
test.log:   tests.log
	@$(TRACE.target)
	@echo "# to show differences with xxdiff, use: $(MAKE_COMMAND) $@-compare"


# collect targets in this file
ALL.test.test  += tests tests.quick tests.log tests.quick.log

.PHONY: test tests

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
test.*.log-compare  \# pattern rule for test.log-compare$(_NL)\
test.*.log-move     \# pattern rule for test.log-move$(_NL)\
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

EXE.log-diff        = xxdiff --geometry 1600x1000

# default prefix, may be redifined per target
TEST.target_prefix  = testcmd-
TEST.target_logfile = $(TEST.logdir)/testcmd-

# default suffix for logfiles
TEST.log-suffix     = -$(_TODAY_)

define _test_log-compare
	cd $(TEST.logdir) && \
	for f in $(TEST.target_prefix)*.log; do \
	    [ -f $${f}$(TEST.log-suffix) ] || continue ; \
	    $(EXE.log-diff) $${f} $${f}$(TEST.log-suffix) >/dev/null 2>&1 ; \
	done
endef

define _test_log-move
	cd $(TEST.logdir) && \
	for f in $(TEST.target_prefix)*.log; do \
	    [ -f $${f}$(TEST.log-suffix) ] || continue ; \
	    mv $${f}$(TEST.log-suffix) $${f} ; \
	done
endef

_test_log_hint  = \# see also: $(MAKE_COMMAND) help.test.log-info

test.log-compare-hint:
	@echo ""
	@echo "# to show differences with xxdiff, use: $(MAKE_COMMAND) $(MAKECMDGOALS)-compare"
	@echo "$(_test_log_hint)"

test.%.log-compare:
	-$(_test_log-compare)
	@echo ""
	@echo "# to move new files to .log , use: $(MAKE_COMMAND) test.$*.log-move"
	@echo "$(_test_log_hint)"

test.%.log-move:
	$(_test_log-move)

test.log-compare:
	-$(_test_log-compare)
	@echo ""
	@echo "# to move new files to .log , use: $(MAKE_COMMAND) test.log-move"
	@echo "$(_test_log_hint)"

test.log-move:
	$(_test_log-move)


ALL.tests      += # nothing added here!

