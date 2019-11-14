#! /usr/bin/make -rRf
#?
#? DESCRIPTION
#?      For more details please see
#?          ../Makefile  Makefile  Makefile.help  Makefile.pod
#?      make help.test.tcl
#?
#? VERSION
#?      @(#) Makefile.tcl 1.29 19/11/14 20:28:36
#?
#? AUTHOR
#?      18-apr-18 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

HELP-help.test.tcl  = targets for testing '$(Project).tcl'

_SID.tcl           := 1.29

_MYSELF.tcl        := t/Makefile.tcl
ALL.includes       += $(_MYSELF.tcl)
ALL.inc.type       += tcl
ALL.help.tests     += help.test.tcl

ifeq (,$(_SID.test))
    -include t/Makefile
endif

TEST.tcl.hosts      = localhost
ifdef TEST.hosts
    TEST.tcl.hosts  = $(TEST.hosts)
endif

first-tcl-target-is-default: help.test.tcl

help.test.tcl:        HELP_TYPE = tcl
help.test.tcl-v:      HELP_TYPE = tcl
help.test.tcl-vv:     HELP_TYPE = tcl

HELP-_tcl1          = _________________________________________ testing GUI tool _
HELP-test.tcl       = test functionality of '$(SRC.tcl)'
HELP-test.tcl.log   = same as test.tcl but store output in '$(TEST.logdir)/'
HELP-_tcl2          = ________________________________________________ GUI tests _
HELP-GUI-not-yet    = not yet implemented ...

HELP.tcl            = # no special documentation yet
HELP.test.tcl.all   = # no special documentation yet

# SEE Make:target name
# SEE Make:target name prefix

testcmd-tcl%:               EXE.pl      = ../o-saft.tcl
testcmd-tcl%:               TEST.init   = +quit
    # ensure that o-saft.tcl exits and does not build the GUI

testcmd-tcl+VERSION_%:      TEST.args  += +VERSION
testcmd-tcl--version_%:     TEST.args  += --version
testcmd-tcl--rc_%:          TEST.args  += --rc
testcmd-tcl--v--load_%:     TEST.args  += --v --load=Makefile
#               returns: different count and TAB tabs: .... .note.oX3XXMake
testcmd-tcl--d_%:           TEST.args  += --d
testcmd-tcl--d2_%:          TEST.args  += --d=2
testcmd-tcl--d6_%:          TEST.args  += --d=6
testcmd-tcl--trace_%:       TEST.args  += --trace
testcmd-tcl--gui_%:         TEST.args  += --gui
testcmd-tcl--v_%:           TEST.args  += --v
testcmd-tcl--v--img_%:      TEST.args  += --v --img
testcmd-tcl--v--text_%:     TEST.args  += --v --text
testcmd-tcl--v-host_%:      TEST.args  += --v host1 host2
testcmd-tcl--v-host-host_%: TEST.args  += --v host1 host2 host3 host4 host5
# TODO:  test with docker
#testcmd-tcl--docker%:       TEST.args  += --docker
#testcmd-tcl--id%:           TEST.args  += --id=docker-ID
#testcmd-tcl--tag%:          TEST.args  += --id=docker-Tag

# test some warnings
testcmd-tcl--v-host1-host2_%:   TEST.args  += --v host1 host2 host3 host4 host5 host6 
testcmd-tcl--unknown_%: TEST.args  += --unknown
#testcmd-tcl--v--load-bad_%:     TEST.args  += --load=/tmp/bad  # file with large value > 5000

test.tcl.log-compare:       TEST.target_prefix  = testcmd-tcl
test.tcl.log-move:          TEST.target_prefix  = testcmd-tcl
test.tcl.log:               TEST.target_prefix  = testcmd-tcl

# SEE Make:target matching
ALL.testtcl     = $(shell awk -F% '/^testcmd-tcl%/{next} /^testcmd-tcl/{arr[$$1]=1}$(_AWK_print_arr_END)' $(_MYSELF.tcl))
ALL.test.tcl    = $(foreach host,$(TEST.tcl.hosts),$(ALL.testtcl:%=%$(host)))
ALL.test.tcl.log= $(ALL.test.tcl:%=%.log)

test.tcl.all:   $(ALL.test.tcl)
test.tcl:       test.tcl.all
test.tcl.log:   $(ALL.test.tcl.log) test.log-compare-hint

#_____________________________________________________________________________
#_____________________________________________________________________ test __|

# feed main Makefile
ALL.tests      += $(ALL.test.tcl)
ALL.tests.log  += $(ALL.test.tcl.log)

