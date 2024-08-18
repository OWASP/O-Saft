#!/usr/bin/make -rRf
#?
#? DESCRIPTION
#?      For more details please see
#?          ../Makefile  Makefile  Makefile.help  Makefile.pod
#?      make help.test.tcl
#?
#? VERSION
#?      @(#) Makefile.tcl 3.7 24/08/18 19:20:02
#?
#? AUTHOR
#?      18-apr-18 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

HELP-help.test.tcl  = targets for testing '$(O-Project).tcl'

O-SID.tcl          := 3.7
O-SELF.tcl         := t/Makefile.tcl
ALL.includes       += $(O-SELF.tcl)
ALL.inc.type       += tcl
ALL.help.tests     += help.test.tcl

first-tcl-target-is-default: help.test.tcl

ifeq (,$(O-SID.test))
    -include t/Makefile
endif

TEST.tcl.hosts      = localhost
ifdef TEST.hosts
    TEST.tcl.hosts  = $(TEST.hosts)
endif

help.test.tcl:        HELP_TYPE = tcl
help.test.tcl-v:      HELP_TYPE = tcl
help.test.tcl-vv:     HELP_TYPE = tcl

HELP-_tcl1          = _________________________________________ testing GUI tool _
HELP-test.tcl       = test functionality of '$(SRC.tcl)'
HELP-test.tcl.log   = same as test.tcl but store output in '$(TEST.logdir)/'
HELP-test.tclinteractive= test functionality of '$(SRC.tcl) with GUI'
HELP-test.tclinteractive.log = same as test.tclinterive but store output in '$(TEST.logdir)/'
HELP-test.GUI       = alias for test.tclinteractive (user interaction required)
HELP-_tcl2          = ________________________________________________ GUI tests _

HELP.tcl            = # no special documentation yet
HELP.test.tcl.all   = # no special documentation yet

# SEE Make:target name
# SEE Make:target name prefix

testarg-tcl-o-saft.tcl_%:               EXE.pl      = ../$(SRC.tcl)
testarg-tcl-o-saft.tcl_%:               TEST.init   = localhost +quit
    # ensure that o-saft.tcl exits and does not build the GUI

LIST.tcl.args  := \
	+VERSION --version --d --d=2 --d=6 --trace --v \
	--rc  --rc=unknown --no-rc \
	--gui --gui-layout=classic --gui-layout=tablet \
	--test-osaft --test-docs   --unknown

# some special targets
testarg-tcl-o-saft.tcl_--no-rc:         TEST.init  += --d
testarg-tcl-o-saft.tcl_--rc-invalid:    TEST.init  += --d
testarg-tcl-o-saft.tcl_--d--no-docs:    TEST.args  += --d --no-docs
testarg-tcl-o-saft.tcl_--d--load:       TEST.args  += --d --load=Makefile
#               returns: different count and TAB tabs: .... .note.oX3XXMake
testarg-tcl-o-saft.tcl_--d--img:        TEST.args  += --d --img   --gui-layout=classic
testarg-tcl-o-saft.tcl_--d--text:       TEST.args  += --d --text  --gui-layout=classic
testarg-tcl-o-saft.tcl_--d-host:        TEST.args  += --d host1 host2
testarg-tcl-o-saft.tcl_--d-host-host:   TEST.args  += --d host1 host2 host3 host4 host5
# test some warnings
testarg-tcl-o-saft.tcl_--d-host1-host2: TEST.args  += --d host1 host2 host3 host4 host5 host6 
#testarg-tcl---d--load-bad_%:TEST.args  += --load=/tmp/bad  # file with large value > 5000
# TODO:  to be implemented
#--load=EXAMPLE
# TODO:  test with docker
#testarg-tcl-o-saft.tcl_--id:            TEST.args  += --id=docker-ID
#testarg-tcl-o-saft.tcl_--tag:           TEST.args  += --id=docker-Tag
#testarg-tcl-o-saft.tcl_--d--gen-docs:   TEST.args  += --d --gen-docs
    # --gen-docs should be used with o-saft.pl only, see Makefile.hlp

ifndef tcl-macros-generated
    $(call GEN.targets,testarg,tcl,-$(SRC.tcl),$(SRC.tcl),LIST.tcl.args,TEST.args,TEST.dumm)
endif
ALL.test.tcl   += \
	testarg-tcl-o-saft.tcl_--d--no-docs testarg-tcl-o-saft.tcl_--d--load \
	testarg-tcl-o-saft.tcl_--d--img     testarg-tcl-o-saft.tcl_--d--text \
	testarg-tcl-o-saft.tcl_--d-host     testarg-tcl-o-saft.tcl_--d-host-host \
	testarg-tcl-o-saft.tcl_--d-host1-host2
ALL.test.tcl.log= $(ALL.test.tcl:%=%.log)

# test command which require user interaction (in GUI)
testarg-tclinteractive-%:   EXE.pl      = ../$(SRC.tcl)
testarg-tclinteractive-%:   TEST.init   = $(TEST.host)
testarg-tclinteractive---gui--gui-classic:  TEST.args  += --gui --gui-layout=classic
testarg-tclinteractive---gui--gui-tablet:   TEST.args  += --gui --gui-layout=tablet
testarg-tclinteractive---gui--docker:       TEST.args  += --gui --docker
testarg-tclinteractive---test-tcl:          TEST.args  += --test-tcl

# *test-interactive* targets are not added to common variables,
# because they cannot be used in scripted make
ALL.testtclinteractive     := testarg-tclinteractive---test-tcl \
	testarg-tclinteractive---gui--gui-classic \
	testarg-tclinteractive---gui--gui-tablet \
	testarg-tclinteractive---gui--docker
ALL.test.tclinteractive     = $(foreach host,$(TEST.tcl.hosts),$(ALL.testtclinteractive:%=%$(host)))
ALL.test.tclinteractive.log = $(ALL.test.tclinteractive:%=%.log)
test.tclinteractive:          $(ALL.test.tclinteractive)
test.tclinteractive.log:      $(ALL.test.tclinteractive.log)
test.GUI:           test.tclinteractive
test.GUI.log:       test.tclinteractive.log

test.tcl.log-compare:       TEST.target_prefix  = testarg-tcl-
test.tcl.log-move:          TEST.target_prefix  = testarg-tcl-
test.tcl.log:               TEST.target_prefix  = testarg-tcl-

test.tcl:           $(ALL.test.tcl)
test.tcl.log:       $(ALL.test.tcl.log) test.log-compare-hint
