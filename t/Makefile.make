#! /usr/bin/make -rRf
#?
#? NAME
#?      Makefile    - makefile for testing Makefiles
#?
#? SYNOPSYS
#?      make [options] [target] [...]
#?
#? DESCRIPTION
#?      Makefile testing targets in all Makefiles (mainly  help*  targets).
#?
#? LIMITATIONS
#?       Requires GNU Make > 2.0.
#?
# HACKER's INFO
#    For details please see
#           ../Makefile  Makefile.help  Makefile.template
#
#? VERSION
#?      @(#) Makefile.make 1.7 19/09/11 23:27:31
#?
#? AUTHOR
#?      19-jul-19 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

_SID.make       = 1.7

_MYSELF.make    = t/Makefile.make
ALL.includes   += $(_MYSELF.make)
ALL.inc.type   += make

MAKEFLAGS      += --no-builtin-variables --no-builtin-rules
.SUFFIXES:

first-make-target-is-default: help.test.make

ALL.help.tests += help.test.make
help.test.make:     HELP_TYPE = make
help.test.make-v:   HELP_TYPE = make


HELP-help.test.make = targets for testing Makefile (help*) targets

ifeq (,$(_SID.test))
    -include t/Makefile
endif

HELP-_makefile1 = _____________________________________ testing help targets _
HELP-help.make.doc  = print documentation about available Makefile.*
HELP-test.make      = test help* targets of our Makefiles
HELP-test.make.log  = same as test.make but store output in '$(TEST.logdir)/'
HELP-test.make.log-compare  = compare results of test.make.log (if any)

HELP.make       = $(_NL)\
\# Note that  test.make  uses "make help.test.*" to show each Makefile's$(_NL)\
\# documentation. In contrast,  test.hlp  uses "o-saft.pl --help*"  to show$(_NL)\
\# (user-)documentation of "o-saft.pl"$(_NL)\

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

# special/indivisual help.* targets in Makefiles
ARGS.helpmake   = help              help.all            help.help.all-v \
		  help.doc          help.doc.all        help.syntax \
		  help.test.internal help.test.makevars help.test.log-info  \
		  help.makefiles.doc
# Makeile-specific help.test.* targets
# pod and template are missing in $(ALL.inc.type) because they are not included
ARGS.makefiles  = $(ALL.inc.type) pod template
ARGS.helpmake  += $(ARGS.makefiles:%=help.test.%)
ARGS.helpmake  += $(ARGS.makefiles:%=help.test.%.all)

ALL.help       += help.makefiles.doc
# contribution to Makefile.help

# TODO: help.test.help, help.help  may exist twice

ALL.test.make      += $(ARGS.helpmake:%=testarg-make-%)
ALL.test.make.log  += $(ALL.test.make:%=%.log)

testarg-make%:      EXE.pl      = $(MAKE)
testarg-make%:      TEST.init   =

$(foreach arg, $(ARGS.helpmake), $(eval testarg-make-$(arg): TEST.args = $(arg)) )

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

