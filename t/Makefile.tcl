#! /usr/bin/make -rRf
#?
#? NAME
#?      Makefile        - makefile for testing o-saft.tcl
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
#           ../Makefile  Makefile.help  Makefile.template 
#
#? VERSION
#?      @(#) Makefile.tcl 1.17 19/03/19 22:57:58
#?
#? AUTHOR
#?      18-apr-18 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

_SID.tcl        = 1.17

_MYSELF.tcl     = t/Makefile.tcl
_MY.includes   += $(_MYSELF.tcl)
_MY.inc.type   += tcl

first-tcl-target-is-default: help.test.tcl

ALL.help.test  += help.test.tcl

HELP-help.test.tcl  = print targets for testing GUI '$(Project).tcl'
help.test.tcl:      _HELP_TYP__ = tcl
help.test.tcl-v:    _HELP_TYP__ = tcl
help.test.tcl-vv:   _HELP_TYP__ = tcl

ifeq (,$(_SID.test))
    -include t/Makefile
endif

TEST.tcl.hosts      = localhost
ifdef TEST.hosts
    TEST.tcl.hosts  = $(TEST.hosts)
endif


HELP-_tcl1          = _________________________________________ testing GUI tool _
HELP-test.tcl       = test functionality of '$(SRC.tcl)'
HELP-test.tcl.log   = same as test.tcl but store output in '$(TEST.logdir)/'
HELP-_tcl2          = ________________________________________________ GUI tests _
HELP-GUI-not-yet    = not yet implemented ...

HELP.tcl            = # no special documentation yet
HELP.test.tcl.all   = # no special documentation yet

# SEE Make:target name
# SEE Make:target name prefix

testcmd-tcl%:                   EXE.pl      = ../o-saft.tcl
testcmd-tcl%:                   TEST.init   = +quit
    # ensure that o-saft.tcl exits and does not build the GUI

testcmd-tclverb+VERSION_%:      TEST.args  += +VERSION
testcmd-tclverb--version_%:     TEST.args  += --version
testcmd-tclverb--rc_%:          TEST.args  += --rc
testcmd-tclverb--v--load_%:     TEST.args  += --v --load=Makefile
#               returns: TAB tabs: .... .note.oX1XX1
testcmd-tclverb--d_%:           TEST.args  += --d
testcmd-tclverb--v_%:           TEST.args  += --v
testcmd-tclverb--v--img_%:      TEST.args  += --v --img
testcmd-tclverb--v--text_%:     TEST.args  += --v --text
testcmd-tclverb--v-host_%:      TEST.args  += --v host1 host2
testcmd-tclverb--d2_%:          TEST.args  += --d=2
testcmd-tclverb--d6_%:          TEST.args  += --d=6
#testcmd-tclverb--v--load_%: TEST.args  += --v --load=/tmp/some-file
    # TODO:  compare results of testcmd-tclverb--v with
    #           testcmd-tclverb--v--img, testcmd-tclverb--v--text, testcmd-tclcmd-verb--v-host
#testcmd-tclverb--trace_%:   TEST.args  += --trace
    # not useful, as there will be no events
testcmd-tclhelp--help_%:        TEST.args  += --help
testcmd-tclhelp--help-flow_%:   TEST.args  += --help-flow
testcmd-tclhelp--help-procs_%:  TEST.args  += --help-procs
testcmd-tclhelp--help-descr_%:  TEST.args  += --help-descr
testcmd-tclhelp--help-o-saft_%: TEST.args  += --help-o-saft

# test some warnings
#testcmd-tclargs-unknown_%: TEST.args  += unknown
testcmd-tclargs--v-host1-host2_%:   TEST.args  += --v host1 host2 host3 host4 host5 host6 
#testcmd-tclargs--v--load-bad_%:     TEST.args  += --load=/tmp/bad  # file with large value > 5000

test.tcl.log-compare:  _TEST_log_prefix = testcmd-tcl
test.tcl.log-move:     _TEST_log_prefix = testcmd-tcl
test.tcl.log:          _TEST_log_prefix = testcmd-tcl

# SEE Make:target matching
ALL.testtcl     = $(shell awk -F% '/^testcmd-tcl%/{next} /^testcmd-tcl/{arr[$$1]=1}$(_AWK_print_arr_END)' $(_MYSELF.tcl))
ALL.test.tcl    = $(foreach host,$(TEST.tcl.hosts),$(ALL.testtcl:%=%$(host)))
ALL.test.tcl.log= $(ALL.test.tcl:%=%.log)

test.tcl.all:   $(ALL.test.tcl)
test.tcl:       test.tcl.all
test.tcl.log:   $(ALL.test.tcl.log) test.log-compare-hint

test.tcl-%:     test.tcl.internal test.tcl.all
	@$(EXE.dummy)

.PHONY: test.tcl.log

#_____________________________________________________________________________
#_____________________________________________________________________ test __|

# feed main Makefile
ALL.tests      += $(ALL.test.tcl)
ALL.tests.log  += $(ALL.test.tcl.log)

