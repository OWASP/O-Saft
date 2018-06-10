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
#       For details please see ../Makefile .
#
#       Naming conventions for targets see ../Makefile.help .
#
#       TODO:
#          * include Makefile.* should be generic
#          * unifiy test.warnings.log and test.tests.log (should use same target)
#          * rename ALL.tests and ALL.test.log (too similar to ALL.test)
#
#? VERSION
#?      @(#) Makefile 1.10 18/06/10 08:59:02
#?
#? AUTHOR
#?      18-apr-18 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

_SID.test   = 1.10

MAKEFLAGS  += --no-builtin-variables --no-builtin-rules
.SUFFIXES:

ifndef ALL.Makefiles
    -include test/Makefile.inc
        # defines macros if called directly (not from ../Makefile)
    MAKE = $(MAKE_COMMAND) -f $(firstword $(MAKEFILE_LIST))
        # redefine MAKE if not called from ../Makefile with proper makefile
        # makefile given with -f option is first in MAKEFILE_LIST, usually
endif

ifeq (,$(_SID.help))
    -include    Makefile.help
    -include ../Makefile.help
endif

ALL.Makefiles  += test/Makefile

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

#_____________________________________________________________________________
#________________________________________________________________ variables __|

# test tools (part of distribution)
TEST.dir        = test
TEST.do         = SSLinfo.pl \
		  o-saft_bench \
		  critic_345.sh \
		  test-bunt.pl.txt \
		  test-o-saft.cgi.sh
TEST.rc         = .perlcriticrc
SRC.test        = \
		  $(TEST.do:%=$(TEST.dir)/%) \
		  $(TEST.rc:%=$(TEST.dir)/%)
ALL.test        = $(SRC.test)

# internal used tools (paths hardcoded!)
EXE.bench       = test/o-saft_bench
EXE.test.bunt   = test/test-bunt.pl.txt

_TODAY_         = $(shell date +%Y""%m%d)

TEST.host       = localhost
TEST.hosts      =
                # list of hosts provided by Makefile.extern

#_____________________________________________________________________________
#_____________________________________________________ internal test target __|

# internal information (nothing related to $(Project))
# Note that the $(_SID*) variables indicate if a sub-makefile was included
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
	@echo '# $$(TEST.dir)      = $(TEST.dir)'
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
	@echo '# $$(.VARIABLES)    = $(.VARIABLES)'

#_____________________________________________________________________________
#______________________________________________________ targets for testing __|

# FIXME: some of above HELP-* should be extracted from test/Makefile.*

# Testing for messages (i.e **WARNING) works as follows:
#   call $(EXE.pl) with command and/or options in question
#   then search (grep) output for message (number in case of warnings)
# For some behaviours of $(EXE.pl) a RC-file is required.
# For testing all different warning-* targets, the pattern rule  message-% is
# used, which gets the message number from the automatic variable $*  and the
# arguments for $(SRC.pl) with following Makefile variables:
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
message-%: $(SRC.pl)
	@$(TARGET_VERBOSE)
	@-if expr "$(TEST.args)" ":" "^TODO" >/dev/null ; then \
	    echo "$@:    $(TEST.args)"; \
	else \
	    echo "$(EXE.pl) $(TEST.args) 2>&1 | grep $* " ; \
	    echo "$(TEST.rc)" > $(_TMP.rc) ; \
	    $(EXE.pl) $(TEST.args) 2>&1 | grep $* ; \
	    rm -f $(_TMP.rc) ; \
	fi
# following removed above, too noicy:
#            echo "echo '$(TEST.rc)' > $(_TMP.rc)" ; 

warning-%: message-%
	@echo -n ""

# target succeeds if message is missing
# TODO: need more examples beside those in test/Makefile.cgi
no.message-%:
	@$(TARGET_VERBOSE)
	@echo "$(TEST.rc)" > $(_TMP.rc)
	$(EXE.pl) $(TEST.args) 2>&1 | awk '/ $*/{exit 1}'
	@rm -f $(_TMP.rc)

#_____________________________________________________________________________
#__________________________________________________ include testing targets __|

# includes are done explicitly instead of:
#  include test/Makefile.*
# to avoid multiple inlcudes of the same file, which would result in make
# errors complaining about target redfefinitions

ifeq (,$(_SID.warnings))
    -include test/Makefile.warnings
endif

ifeq (,$(_SID.cmds))
    -include test/Makefile.cmds
endif

ifeq (,$(_SID.ext))
    -include test/Makefile.ext
endif

ifeq (,$(_SID.cgi))
    -include test/Makefile.cgi
endif

ifeq (,$(_SID.misc))
    -include test/Makefile.misc
endif

ifeq (,$(_SID.critic))
    -include test/Makefile.critic
endif

#_____________________________________________________________________________
#_____________________________________________________________________ test __|

# targets must be at end of Makefile because of macros used as dependencies

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

test:       tests
test.log:   tests.log

.PHONY: test tests

