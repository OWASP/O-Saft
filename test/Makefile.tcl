#! /usr/bin/make -rRf
#?
#? NAME
#?      Makefile    - makefile for testing o-saft.tcl
#?
#? SYNOPSYS
#?      make [options] [target] [...]
#?
#? DESCRIPTION
#?      Makefile containing general testing o-saft.tcl .
#?
#? LIMITATIONS
#?      Requires GNU Make > 2.0.
#?
# HACKER's INFO
#       For details please see
#           ../Makefile  ../Makefile.help  Makefile.template 
#
#? VERSION
#?      @(#) Makefile.tcl 1.1 18/06/12 18:27:52
#?
#? AUTHOR
#?      18-apr-18 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

_SID.tcl    = 1.1

MAKEFLAGS  += --no-builtin-variables --no-builtin-rules --no-print-directory
.SUFFIXES:

first-tcl-target-is-default: help.test.tcl

ifeq (,$(_SID.test))
    -include test/Makefile
endif

_MYSELF.tcl         = test/Makefile.tcl
# must be hardcoded because $(firstword $(MAKEFILE_LIST)) gets the calling file
ALL.Makefiles      += $(_MYSELF.tcl)

TEST.tcl.hosts      = localhost
ifdef TEST.hosts
    TEST.tcl.hosts  = $(TEST.hosts)
endif


MORE-tcl         = " \
\#               ______________________________________________ GUI tests _$(_NL)\
 help.test.tcl.all  - print all targets$(_NL)\
 test.tcl        - test functionality of $(SRC.tcl)$(_NL)\
 test.tcl.log    - same as test.tcl but store output in $(TEST.dirlog)/$(_NL)\
"

HELP-help.test.tcl  = print targets for GUI testing
help.test.tcl:
	@echo " $(_HELP_LINE_)$(_NL) $(_HELP_INFO_)$(_NL) $(_HELP_LINE_)$(_NL)"
	@echo $(MORE-tcl)    ; # no quotes!

help.test.tcl.all:
	@echo "# list of all targets:"
	@echo "$(ALL.test.tcl)"                                                 
	@echo "#"

test.tcl.internal:
	@echo "# TEST.file:       $(TEST.file)"
	@echo "# TEST.tcl.hosts:  $(TEST.tcl.hosts)"
	@echo "# ALL.testtcl:     $(words $(ALL.testtcl))  : $(ALL.testtcl)"
	@echo "# ALL.test.tcl:    $(words $(ALL.test.tcl)) : $(ALL.test.tcl)"
	@echo "# testcmd-tcl%:    TEST.init = +quit"
	@echo "# -------------------------------------------------------------"

.PHONY: help.test.tcl test.tcl.internal

testcmd-tcl%:     EXE.pl      = ../o-saft.tcl
testcmd-tcl%:     TEST.init   = +quit
    # ensure that o-saft.tcl exits and does not build the GUI

testcmd-tcl001_%: TEST.args  += +VERSION
testcmd-tcl002_%: TEST.args  += --version
testcmd-tcl003_%: TEST.args  += --rc
testcmd-tcl004_%: TEST.args  += --v --load=Makefile
#               returns: TAB tabs: .... .note.oX1XX1
testcmd-tcl005_%: TEST.args  += --d
testcmd-tcl006_%: TEST.args  += --v
testcmd-tcl007_%: TEST.args  += --v --img
testcmd-tcl008_%: TEST.args  += --v --text
testcmd-tcl009_%: TEST.args  += --v host1 host2
# TODO:  compare results of testcmd-tcl006 with
#           testcmd-tcl007, testcmd-tcl008, testcmd-tclcmd-t009
testcmd-tcl020_%: TEST.args  += --help
testcmd-tcl021_%: TEST.args  += --help-flow
testcmd-tcl022_%: TEST.args  += --help-procs
testcmd-tcl023_%: TEST.args  += --help-descr
testcmd-tcl024_%: TEST.args  += --help-o-saft

ALL.testtcl     = $(shell awk -F% '/^testcmd-tcl..._/ {print $$1}' $(_MYSELF.tcl))
ALL.test.tcl    = $(foreach host,$(TEST.tcl.hosts),$(ALL.testtcl:%=%$(host)))
ALL.test.tcl.log= $(ALL.test.tcl:%=%.log)

test.tcl:       $(ALL.test.tcl)
test.tcl.log:   $(ALL.test.tcl.log)

test.tcl-%:     test.tcl.internal test.tcl
	echo -n ""

#_____________________________________________________________________________
#_____________________________________________________________________ test __|

# feed main Makefile
ALL.tests      += $(All.test.tcl)
ALL.tests.log  += test.tcl.log

