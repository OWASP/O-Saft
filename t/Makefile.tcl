#! /usr/bin/make -rRf
#?
#? DESCRIPTION
#?      For more details please see
#?          ../Makefile  Makefile  Makefile.help  Makefile.pod
#?      make help.test.tcl
#?
#? VERSION
#?      @(#) Makefile.tcl 1.36 22/04/04 01:53:53
#?
#? AUTHOR
#?      18-apr-18 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

HELP-help.test.tcl  = targets for testing '$(Project).tcl'

_SID.tcl           := 1.36

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
HELP-test.tclinteractive= test functionality of '$(SRC.tcl) with GUI'
HELP-test.tclinteractive.log = same as test.tclinterive but store output in '$(TEST.logdir)/'
HELP-test.GUI       = alias for test.tclinteractive
HELP-_tcl2          = ________________________________________________ GUI tests _

HELP.tcl            = # no special documentation yet
HELP.test.tcl.all   = # no special documentation yet

# SEE Make:target name
# SEE Make:target name prefix

testcmd-tcl-%:              EXE.pl      = ../o-saft.tcl
testcmd-tcl-%:              TEST.init   = +quit
    # ensure that o-saft.tcl exits and does not build the GUI

testcmd-tcl-+VERSION_%:     TEST.args  += +VERSION
testcmd-tcl---version_%:    TEST.args  += --version
testcmd-tcl---rc_%:         TEST.args  += --rc
testcmd-tcl---v_%:          TEST.args  += --v
testcmd-tcl---v--no-docs_%: TEST.args  += --v --no-docs
testcmd-tcl---v--load_%:    TEST.args  += --v --load=Makefile
#               returns: different count and TAB tabs: .... .note.oX3XXMake
testcmd-tcl---d_%:          TEST.args  += --d
testcmd-tcl---d2_%:         TEST.args  += --d=2
testcmd-tcl---d6_%:         TEST.args  += --d=6
testcmd-tcl---trace_%:      TEST.args  += --trace
testcmd-tcl---gui_%:        TEST.args  += --gui
testcmd-tcl---v_%:          TEST.args  += --v
testcmd-tcl---v--img_%:     TEST.args  += --v --img   --gui-layout=classic
testcmd-tcl---v--text_%:    TEST.args  += --v --text  --gui-layout=classic
testcmd-tcl---v--gen-docs_%:TEST.args  += --v --gen-docs
testcmd-tcl---v-host_%:     TEST.args  += --v host1 host2
testcmd-tcl---v-host-host_%:TEST.args  += --v host1 host2 host3 host4 host5
testcmd-tcl---gui-classic_%:TEST.args  += --gui-layout=classic
testcmd-tcl---gui-tablet_% :TEST.args  += --gui-layout=tablet
testcmd-tcl---test-osaft_%: TEST.args  += --test-osaft
# TODO:  to be implemented
#testcmd-tcl---load-FILE_%:  TEST.args  += --load=EXAMPLE
# TODO:  test with docker
#testcmd-tcl---id%:          TEST.args  += --id=docker-ID
#testcmd-tcl---tag%:         TEST.args  += --id=docker-Tag

# test command wich require user interaction (in GUI)
testcmd-tclinteractive-%:   EXE.pl      = ../o-saft.tcl
testcmd-tclinteractive-%:   TEST.init   =
testcmd-tclinteractive---gui--gui-classic_%: TEST.args  += --gui --gui-layout=classic
testcmd-tclinteractive---gui--gui-tablet_%:  TEST.args  += --gui --gui-layout=tablet
testcmd-tclinteractive---gui--docker_%:      TEST.args  += --gui --docker
testcmd-tclinteractive---test-tcl_%:         TEST.args  += --test-tcl

# test some warnings
testcmd-tcl---v-host1-host2_%:  TEST.args  += --v host1 host2 host3 host4 host5 host6 
testcmd-tcl---unknown_%:    TEST.args  += --unknown
#testcmd-tcl---v--load-bad_%:TEST.args  += --load=/tmp/bad  # file with large value > 5000

# SEE Make:target matching
ALL.testtcl         = $(shell awk -F% '/^testcmd-tcl-%/{next} /^testcmd-tcl-/{arr[$$1]=1}$(_EXE.print_arr_END.awk)' $(_MYSELF.tcl))
ALL.test.tcl        = $(foreach host,$(TEST.tcl.hosts),$(ALL.testtcl:%=%$(host)))
ALL.test.tcl.log    = $(ALL.test.tcl:%=%.log)

# *test-interactive* targets are not added to coomon variables,
# they cannot be used in scripted make, but need to be startet interactive
ALL.testtclinteractive      = $(shell awk -F% '/^testcmd-tclinteractive-%/{next} /^testcmd-tclinteractive-/{arr[$$1]=1}$(_EXE.print_arr_END.awk)' $(_MYSELF.tcl))
ALL.test.tclinteractive     = $(foreach host,$(TEST.tcl.hosts),$(ALL.testtclinteractive:%=%$(host)))
ALL.test.tclinteractive.log = $(ALL.test.tclinteractive:%=%.log)
test.tclinteractive:          $(ALL.test.tclinteractive)
test.tclinteractive.log:      $(ALL.test.tclinteractive.log)
test.GUI:           test.tclinteractive
test.GUI.log:       test.tclinteractive.log

test.tcl.log-compare:       TEST.target_prefix  = testcmd-tcl-
test.tcl.log-move:          TEST.target_prefix  = testcmd-tcl-
test.tcl.log:               TEST.target_prefix  = testcmd-tcl-

test.tcl:           $(ALL.test.tcl)
test.tcl.log:       $(ALL.test.tcl.log) test.log-compare-hint
