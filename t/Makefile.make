#! /usr/bin/make -rRf
#?
#? DESCRIPTION
#?      For more details please see
#?          ../Makefile  Makefile  Makefile.help  Makefile.pod
#?      make help.test.make
#?
#? VERSION
#?      @(#) Makefile.make 1.12 19/11/20 00:08:17
#?
#? AUTHOR
#?      19-jul-19 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

HELP-help.test.make = targets for testing Makefile help* targets

_SID.make          := 1.12

_MYSELF.make       := t/Makefile.make
ALL.includes       += $(_MYSELF.make)
ALL.inc.type       += make
ALL.help.tests     += help.test.make

ifeq (,$(_SID.test))
    -include t/Makefile
endif

first-make-target-is-default: help.test.make

help.test.make:     HELP_TYPE = make
help.test.make-v:   HELP_TYPE = make
help.test.make-vv:  HELP_TYPE = make

HELP-_makefile1 = _____________________________________ testing help targets _
HELP-help.make.doc  = print documentation about available Makefile.*
HELP-test.make      = test help* targets of our Makefiles
HELP-test.make.log  = same as test.make but store output in '$(TEST.logdir)/'
HELP-test.make.log-compare  = compare results of test.make.log (if any)

HELP.make       = $(_NL)\
\# Note that  test.make  uses "make help.test.*" to show each Makefile's$(_NL)\
\# documentation. In contrast,  test.hlp  uses "o-saft.pl --help*"  to show$(_NL)\
\# (user-)documentation of "o-saft.pl"$(_NL)\

# dumm '

HELP.test.make.all  = # no special documentation yet

# Following target lists the used (included)  t/Makefile.* , each with its
# description as defined in the file itself in the  HELP-help.text.* macro
_HELP-maketitle = \#__________________________________ purpose of t/Makefile.* _
_HELP.maketitle = $(ALL.inc.type:%=help-makefiletitle-%)
_help.makefiles.doc:
	@$(TRACE.target)
	@echo "\n\t\t$(_HELP-maketitle)"
	@$(MAKE) -s $(_HELP.maketitle)
help.makefiles.doc:   HELP_HEAD = $(HELP_INFO)
help.makefiles.doc:  _help.HEAD _help.makefiles.doc
	@$(TRACE.target)

HELP-testarg-make-help.test*  = test help.test.* targets of Makefiles
HELP-testarg-make-s-ALL.test* = test ALL.test.* variables of Makefiles
# special/indivisual help.* targets in Makefiles
LIST.helpmake  := help              help.all            help.help.all-v \
		  help.doc          help.doc.all        help.syntax \
		  help.test.internal help.test.makevars help.test.log-info  \
		  help.makefiles.doc
# Makefile-specific help.test.* targets
# pod and template are missing in $(ALL.inc.type) because they are not included
LIST.makefiles  = $(ALL.inc.type) pod template
LIST.helpmake  += $(LIST.makefiles:%=help.test.%)
LIST.helpmake  += $(LIST.makefiles:%=help.test.%.all)

# Makeile-specific ALL.test.* variables
LIST.testmake  += $(LIST.makefiles:%=s-ALL.test.%)

ALL.help       += help.makefiles.doc
# contribution to Makefile.help

# TODO: help.test.help, help.help  may exist twice

ALL.test.make      += $(LIST.helpmake:%=testarg-make-%)
ALL.test.make      += $(LIST.testmake:%=testarg-make-%)
ALL.test.make.log  += $(ALL.test.make:%=%.log)

testarg-make%:      EXE.pl      = $(MAKE)
testarg-make%:      TEST.init   =
testarg-make%:      TRACE.target= echo "\#$(EXE.pl) $(TEST.init) $(TEST.args)"
    # targets should print the command, the TRACE.target variable is misused
    # for that (assuming that all target use $(TRACE.target) ).

$(foreach arg, $(LIST.helpmake), $(eval testarg-make-$(arg): TEST.args = $(arg)) )
$(foreach arg, $(LIST.testmake), $(eval testarg-make-$(arg): TEST.args = $(arg)) )

test.make.all:      $(ALL.test.make)
test.make:          test.make.all
test.make.log:      $(ALL.test.make.log) test.log-compare-hint

test.make.log-compare:  TEST.target_prefix  = testcmd-make
test.make.log-move:     TEST.target_prefix  = testcmd-make
test.make.log:          TEST.target_prefix  = testcmd-make

.PHONY: test.make.log

# feed main Makefile
ALL.tests          += $(ALL.test.make)
ALL.tests.log      += $(ALL.test.make.log)

