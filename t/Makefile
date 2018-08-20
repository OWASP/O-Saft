#! /usr/bin/make -rRf
#?
#? NAME
#?      Makefile    - makefile for testing O-Saft
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
#           ../Makefile  ../Makefile.help  Makefile.template
#
#       TODO:
#          * include Makefile.* should be generic
#          * unify test.warnings.log and test.tests.log (should use same target)
#          * rename ALL.tests and ALL.tests.log (too similar to ALL.test)
#
#? VERSION
#?      @(#) Makefile 1.20 18/08/21 01:21:28
#?
#? AUTHOR
#?      18-apr-18 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

_SID.test       = 1.20

_MYSELF.test    = t/Makefile
ALL.includes   += $(_MYSELF.test)

MAKEFLAGS      += --no-builtin-variables --no-builtin-rules
.SUFFIXES:

first-test-target-is-default: help.test

ifndef ALL.Makefiles
    -include t/Makefile.inc
    # defines macros if called directly (not from ../Makefile)
endif

ifeq (,$(_SID.help))
    -include    Makefile.help
    -include ../Makefile.help
    # it's intended that only one will be found
endif

#_____________________________________________________________________________
#___________________________________________________________ default target __|

# TODO: following targets are not fully generic, need to be adapted here
help.test:
	@echo " $(_HELP_LINE_)$(_NL) $(_HELP_INFO_)$(_NL) $(_HELP_LINE_)$(_NL)"
	@echo $(MORE-cmds)    ; # no quotes!
	@echo " $(_HELP_LINE_)"
	@echo $(MORE-warnings)
	@echo " $(_HELP_LINE_)"
	@echo $(MORE-cgi)
	@echo " $(_HELP_LINE_)"
	@echo $(MORE-ext)
	@echo " $(_HELP_LINE_)"
	@echo $(MORE-misc)
	@echo " $(_HELP_LINE_)"
	@echo $(MORE-critic)
	@echo " $(_HELP_LINE_)"
	@echo $(MORE-env)
	@echo " $(_HELP_LINE_)"

help.test.all:
	@echo "# individual targets for tests"
	@$(MAKE) -s echo=ALL.tests     echo
	@echo ""
	@$(MAKE) -s echo=ALL.tests.log echo
	@echo ""
	@echo "# individual targets for testing warnings"
	@$(MAKE) -s echo=ALL.warnings  echo
	@echo ""
	@echo "# for more details, use following targets"
	@echo "  $(MAKE) t-test"
	@echo "  $(MAKE) t-warn"
	@echo "  $(MAKE) t-critic"
	@echo ""

.PHONY: help.test help.test.all

# FIXME: some of above HELP-* should be extracted from t/Makefile.*

#_____________________________________________________________________________
#________________________________________________________________ variables __|

# test tools (part of distribution)
TEST.dir        = t
TEST.logdir     = $(TEST.dir)/log

# following defined in ../Makefile
# TEST.do  =
# SRC.test =
# ALL.test =

# defined in other t/Makefile*
# ALL.tests =

# internal used tools (paths hardcoded!)
EXE.bench       = t/o-saft_bench
EXE.test.bunt   = t/test-bunt.pl.txt

_TODAY_         = $(shell date +%Y""%m%d)

# following may be redefined in included Makefiles
# TEST.init       = --header
# TEST.args       =

# macro Lname for list of hostnames needs to be unique in each Makefile*
# otherwise some targets in other Makefile* get confused
#TEST.host       = localhost
#TEST.hosts      =

MORE-env        = " \
\# Following variables are intended to be used on command line:$(_NL)\
\#$(_NL)\
\#   EXE.pl      - program to perform tests, default: $(EXE.pl)$(_NL)\
\#   TEST.init   - arguments and options always passed to EXE.pl; default: $(TEST.init)$(_NL)\
\#   TEST.args   - arguments and options to be passed to EXE.pl per target$(_NL)\
\#   TEST.host   - hostname to be used for tests (when only one is expected)$(_NL)\
\#   TEST.hosts  - list of hostnames to perform tests$(_NL)\
\#   TEST.dir    - directory in which EXE.pl will be executed; default: $(TEST.dir)$(_NL)\
\#   TEST.logdir - directory where results of EXE.pl will be stored; default: $(TEST.logdir)$(_NL)\
\#   TEST.rc     - content of RC-file to be used by $(EXE.pl)$(_NL)\
\#$(_NL)\
\# Keep in mind that following files are located in $(TEST.dir):$(_NL)\
\#   $(EXE.pl)  .o-saft.pl  $(TEST.rc)  .o-saft.tcl$(_NL)\
\# which are used by EXE.pl or other tools used for the tests.$(_NL)\
\# The test targets call  EXE.pl  without a path, so it must be found in the$(_NL)\
\# PATH  environment variable (which should contain .)$(_NL)\
"
#  $(SRC.rc)  may not be defined here, hence hardcoded

#_____________________________________________________________________________
#_____________________________________________________ internal test target __|

# internal information (nothing related to $(Project))
# note that the $(_SID*) variables indicate if a sub-makefile was included
test.file-1:
test,file-2:
test_file-3:
test.target: test.file-1 test,file-2 test_file-3
	@echo 'test.target: test.file-1 test-file-2 test_file-3'
	@echo '# show some private make variables:'
	@echo '# $$(_SID)          = $(_SID)'
	@echo '# $$(_SID.help)     = $(_SID.help)'
	@echo '# $$(_SID.warnings) = $(_SID.warnings)'
	@echo '# $$(_SID.cmds)     = $(_SID.cmds)'
	@echo '# $$(_SID.ext)      = $(_SID.ext)'
	@echo '# $$(_SID.cgi)      = $(_SID.cgi)'
	@echo '# $$(_SID.inc)      = $(_SID.inc)'
	@echo '# $$(PWD)           = $(PWD)'
	@echo '# $$(PWD.dir)L      = $(notdir $(PWD))'
	@echo '# $$(TEST.dir)      = $(TEST.dir)'
	@echo '# $$(TEST.logdir)   = $(TEST.logdir)'
	@echo '# $$(ALL.Makefiles) = $(ALL.Makefiles)'
	@echo '# $$(ALL.includes)  = $(ALL.includes)'
	@echo '# show some make variables:'
	@echo '# $$@  = $@ #'
	@echo '# $$<  = $< #'
	@echo '# $$?  = $? #'
	@echo '# $$^  = $^ #'
	@echo '# $$+  = $+ #'
	@echo '# $$|  = $| #'
	@echo '# $$%  = $% #'
	@echo '# $$*  = $* #'
	@echo '# $$>  = $> #'
	@echo '# $$-  = $- #'
	@echo '# $$D  = $D #'
	@echo '# $$F  = $F #'
	@echo '# $$(MAKE)          = $(MAKE)'
	@echo '# $$(CURDIR)        = $(CURDIR)'
	@echo '# $$(MAKE_COMMAND)  = $(MAKE_COMMAND)'
	@echo '# $$(MAKE_VERSION)  = $(MAKE_VERSION)'
	@echo '# $$(MAKE_HOST)     = $(MAKE_HOST)'
	@echo '# $$(MAKELEVEL)     = $(MAKELEVEL)'
	@echo '# $$(MAKEFILE)      = $(MAKEFILE)'
	@echo '# $$(MAKEFILES)     = $(MAKEFILES)'
	@echo '# $$(MAKEFILE_LIST) = $(MAKEFILE_LIST)'
	@echo '# $$(MAKEFILE_LIST)F= $(firstword $(MAKEFILE_LIST))'
	@echo '# $$(MAKEFILE_LIST)L= $(lastword  $(MAKEFILE_LIST))'
	@echo '# $$(MFLAGS)        = $(MFLAGS)'
	@echo '# $$(MAKEFLAGS)     = $(MAKEFLAGS)'
	@echo '# $$(MAKEOVERRIDES) = $(MAKEOVERRIDES)'
	@echo '# $$(MAKECMDGOALS)  = $(MAKECMDGOALS)'
	@echo '# $$(GNUMAKEFLAGS)  = $(GNUMAKEFLAGS)'
	@echo '# $$(.PRECIOUS)     = $(.PRECIOUS)'
	@echo '# $$(.SECONDARY)    = $(.SECONDARY)'
	@echo '# $$(.INTERMEDIATE) = $(.INTERMEDIATE)'
	@echo '# $$(.SUFFIXES)     = $(.SUFFIXES)'
	@echo '# $$(.VARIABLES)    = $(.VARIABLES)'

#_____________________________________________________________________________
#______________________________________________________ targets for testing __|

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

# Testing for messages (i.e **WARNING) works as follows:
#   call $(EXE.pl) with command and/or options in question
#   then search (grep) output for message (number in case of warnings)
# For some behaviours of $(EXE.pl) a RC-file is required.
# For testing all different warning-* targets, the pattern rule  message-% is
# used, which gets the message number from the automatic variable $*  and the
# arguments for $(SRC.pl) with following Makefile variables:
#   $(TEST.init)    - command, options to be passed to $(EXE.pl)
#   $(TEST.args)    - command, options and hostname to be passed to $(EXE.pl)
#                     +quit  command or  other command and hostname is needed
#                     for testing the warning message
#   $(TEST.rc)      - content of RC-file to be used by $(EXE.pl)
# These variables are set conditinally for each target (see above).
# Some tests are not yet implemented, or difficult to implement. In this case
# $(TEST.args) contains a string starting with "TODO:". The  message-%  target
# tests the variable for this string and then simply prints it. Otherwise the
# check will be performed (see  if - else -fi  in target).
# Note:  even '$(_TMP.rc)'  is generated for each call,  it will only be used
# when requested with the  --rc=$(_TMP.rc)  option.

# target succeeds if message is there
message-%:
	@$(TARGET_VERBOSE)
	@-if expr "$(TEST.args)" ":" "^TODO" >/dev/null ; then \
	    echo "$@:    $(TEST.args)"; \
	else \
	    echo "$(EXE.pl) $(TEST.init) $(TEST.args) 2>&1 | grep $* " ; \
	    echo "$(TEST.rc)" > $(_TMP.rc) ; \
	    cd $(TEST.dir) && $(EXE.pl) $(TEST.init) $(TEST.args) 2>&1 | grep $* ; \
	    _status=$$? ; \
	    rm -f $(_TMP.rc) ; \
	    exit $$_status ; \
	fi
# following removed from above, too noicy:
#            echo "echo '$(TEST.rc)' > $(_TMP.rc)" ;

warning-%: message-%
	@echo -n ""

# target succeeds if message is missing
# TODO: need more examples beside those in t/Makefile.cgi
no.message-%:
	@$(TARGET_VERBOSE)
	@echo "$(TEST.rc)" > $(_TMP.rc)
	$(EXE.pl) $(TEST.init) $(TEST.args) 2>&1 | awk '/ $*/{exit 1}'
	@rm -f $(_TMP.rc)

# The goal for test targets is to perform (test) all commands with all hosts.
# The hostnames are provided in a simple list: $(TEST.hosts) .
# The commands couldn't be provided in a make macro all together, because each
# command may consist of space separated words like: "+info --header".
# Hence each command is defined in the macro  TEST.args, which will be set for
# an individual target, for example: testcmd-001 . We have one target for each
# specific test case, which actually is alist of  commands and options for the
# tool $(EXE.pl) . Note that the trailing  DDD  (001 in example above) is just
# a number to make each target unique.
# To feed the hostname to that target,  the target is defined as  pattern rule
# testcmd-001_% , which means that we can pass the hostname, for example:
# testcmd-001_host.some.tld
# Now we can simply use:  $(TESTS.hosts:%=testcmd-001_%) , which generates one
# target for each host in the list. But that would require to build a list for
# each such target:  testcmd-002_%  and  testcmd-003_%  and so on.
# As we want to perform all these targets with all hostnames,  this would also
# require an additional pattern rule for the hostname part.
# To avoid such a addditional pattern rule for each  testcmd-DDD,  the general
# pattern rule  testcmd-% is used. It handles all the individual targets which
# contain the hostname.
# Unfortunatelly, this pattern contains  DDD_  (for example 001_host.some.tld)
# as hostname.  This  DDD_  prefix must then be removed in the target command,
# the  $(shell awk ...)  does the dirty work.
#
# Note: following does not work (in GNUmake), hence the solution above:
#     testcmd-no1: TEST.args  = +quit $*
#     testcmd-no2: TEST.args := +quit $*
#
# Summary:
#     ### defined in t/Makefile.*
#     # define list of hostnames
#     TEST.hosts    = aa.tld  bb.tld
#     # define the commands to be used for $(EXE.pl) in the target
#     testcmd-00c-%: TEST.args = +cipher
#     testcmd-00i-%: TEST.args = +info
#
#     ### defined below
#     # pattern rule to handle all targets testcmd-DDD_HOSTNAME
#     testcmd-%
#
#     # remove prefix  DDD-  from hostname
#     $(shell awk 'END{h="$*";sub(/^[^_]*-/,"",h);print h}' /dev/null)
#     # or
#     $(shell echo "$*" | awk -F_ '{print $$2}') $(TEST.args)
#     #   00c-aa.tld returns: aa.tld
#
#     ### defined in t/Makefile.*
#     # dynamically generate list of all testcmd-DDD  targets
#     ALL.ext.cmd = $(shell awk -F_ '/^testcmd-[0-9]/{print $$1}' t/Makefile.ext)
#     #   returns: testcmd-00c testcmd-00i
#
#     # dynamically generate list of all testcmd-DDD for all hostnames
#     ALL.by_host   = $(foreach host,$(TEST.hosts),$(ALL.ext.cmd:%=%_$(host)))
#     #   returns: testcmd-00c_aa.tld testcmd-00i_aa.tld testcmd-00c_bb.tld testcmd_00i-bb.tld

testcmd-%:
	@$(TARGET_VERBOSE)
	-cd $(TEST.dir) && $(EXE.pl) $(shell echo "$*" | awk -F_ '{print $$NF}') $(TEST.init) $(TEST.args)
# TODO: need verbose for executed command
# TODO: need to add --no-dns if hostname is an IP

# alias target
test-%: testcmd-%
	@echo -n ""

# Target should create a new logfile, then compare it with the current one. If
# diff  returns nothing, delete newly created logfile,  otherwise rename newly
# created file to name which contains the current date.
# Finally, if current logfile is/was missing, use newly created one:
# "test ... || mv ..." . This ensures that the file exists afterwards.
# Note that all target commands are prefixed with - to avoid make reporting of
# errors if the command fails (as failture is intended, somehow).
# Note that  testcmd-%.log  called from within t/ may return:  is up to date.
# diff's STDERR is discarded (may return: "file does not exist").
testcmd-%.log: $(TEST.logdir)
	@$(TARGET_VERBOSE)
	@$(eval _NEW.log := $(TEST.logdir)/$@-$(_TODAY_))
	@$(MAKE) $(MFLAGS) -s testcmd-$* > $@ 2>&1
	@-diff $(TEST.logdir)/$@ $@ 2>/dev/null \
	    && rm $@ \
	    || mv $@ $(_NEW.log)
	@-test -f $(TEST.logdir)/$@  ||  mv $(_NEW.log) $(TEST.logdir)/$@
	@-ls -l  $(TEST.logdir)/testcmd-$(*)*
# TODO: target should fail if there is a diff

#_____________________________________________________________________________
#__________________________________________________ include testing targets __|

# includes are done explicitly instead of:
#  include t/Makefile.*
# to avoid multiple inlcudes of the same file, which would result in make
# errors complaining about target redefinitions
# for a detailed description see t/Makefile.template

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

ifeq (,$(_SID.cgi))
    -include t/Makefile.cgi
endif

ifeq (,$(_SID.tcl))
    -include t/Makefile.tcl
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
HELP-help.test  = print more targets for testing
HELP-help.test.all  = print available individual targets for testing

tests: TARGET_VERBOSE=echo "\\012\#\# $@: $(EXE.pl) $(TEST.args)"
tests:      $(ALL.tests)
	@echo -n ""
# bench.log

tests.log:  $(ALL.tests.logs)

# aliases for convenience
test:       tests
test.log:   tests.log

.PHONY: test tests

