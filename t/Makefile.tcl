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
#?      @(#) Makefile.tcl 1.10 19/03/07 23:16:48
#?
#? AUTHOR
#?      18-apr-18 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

_SID.tcl        = 1.10

_MYSELF.tcl     = t/Makefile.tcl
ALL.includes   += $(_MYSELF.tcl)
ALL.inc.type   += tcl

first-tcl-target-is-default: help.test.tcl

ifeq (,$(_SID.test))
    -include t/Makefile
endif

TEST.tcl.hosts      = localhost
ifdef TEST.hosts
    TEST.tcl.hosts  = $(TEST.hosts)
endif


HELP.tcl        = "\
\#              _________________________________________ testing GUI tool _$(_NL)\
 test.tcl       - test functionality of '$(SRC.tcl)'$(_NL)\
 test.tcl.log   - same as test.tcl but store output in '$(TEST.logdir)/'$(_NL)\
\#              ________________________________________________ GUI tests _$(_NL)\
\# not yet implemented ...$(_NL)\
"

ALL.help.test  += $(_NL)$(HELP.tcl)

HELP-help.test.tcl  = print targets for testing GUI '$(Project).tcl'

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
#testcmd-tclverb--v--load_%: TEST.args  += --v --load=/tmp/some-file
    # TODO:  compare results of testcmd-tclverb--v with
    #           testcmd-tclverb--v--img, testcmd-tclverb--v--text, testcmd-tclcmd-verb--v-host
testcmd-tclhelp--help_%:        TEST.args  += --help
testcmd-tclhelp--help-flow_%:   TEST.args  += --help-flow
testcmd-tclhelp--help-procs_%:  TEST.args  += --help-procs
testcmd-tclhelp--help-descr_%:  TEST.args  += --help-descr
testcmd-tclhelp--help-o-saft_%: TEST.args  += --help-o-saft

# test some warnings
#testcmd-tclargs-unknown_%: TEST.args  += unknown
testcmd-tclargs--v-host1-host2_%:   TEST.args  += --v host1 host2 host3 host4 host5 host6 
#testcmd-tclargs--v--load-bad_%:     TEST.args  += --load=/tmp/bad  # file with large value > 5000

# SEE Make:target matching
ALL.testtcl     = $(shell awk -F% '($$1 ~ /^testcmd-tcl.../){print $$1}' $(_MYSELF.tcl))
ALL.test.tcl    = $(foreach host,$(TEST.tcl.hosts),$(ALL.testtcl:%=%$(host)))
ALL.test.tcl.log= $(ALL.test.tcl:%=%.log)

test.tcl.all:   $(ALL.test.tcl)
test.tcl:       test.tcl.all
test.tcl.log:   $(ALL.test.tcl.log)

test.tcl-%:     test.tcl.internal test.tcl.all
	echo -n ""

#_____________________________________________________________________________
#_____________________________________________________________________ test __|

# feed main Makefile
ALL.tests      += $(ALL.test.tcl)
ALL.tests.log  += $(ALL.test.tcl.log)

