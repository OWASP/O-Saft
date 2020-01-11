#! /usr/bin/make -rRf
#?
#? DESCRIPTION
#?      For more details please see
#?          ../Makefile  Makefile  Makefile.help  Makefile.pod
#?      make help.test.cmd
#?
#? VERSION
#?      @(#) Makefile.cmd 1.50 20/01/11 09:23:08
#?
#? AUTHOR
#?      18-apr-18 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

HELP-help.test.cmd  = targets for testing '$(SRC.pl)' commands and options

_SID.cmd           := 1.50

_MYSELF.cmd        := t/Makefile.cmd
ALL.includes       += $(_MYSELF.cmd)
ALL.inc.type       += cmd
ALL.help.tests     += help.test.cmd

ifeq (,$(_SID.test))
    -include t/Makefile
endif

TEST.cmd.hosts      = localhost
ifdef TEST.hosts
    TEST.cmd.hosts  = $(TEST.hosts)
endif

first-cmd-target-is-default: help.test.cmd

help.test.cmd:        HELP_TYPE = cmd
help.test.cmd-v:      HELP_TYPE = cmd
help.test.cmd-vv:     HELP_TYPE = cmd

HELP-_cmd1          = _________________________________________ testing commands _
HELP-test.pattern-* = test group of commands with '$(TEST.cmd.hosts)'
HELP-testcmd-*      = test commands with '$(TEST.cmd.hosts)'
HELP-testcmd-*.log  = same as testcmd-* but store output in '$(TEST.logdir)/'
HELP-test.cmd       = test all commands with '$(TEST.cmd.hosts)'
HELP-test.cmd.log   = same as test.cmd but store output in '$(TEST.logdir)/'
HELP-_cmd2          = ________________________________ testing a special command _
HELP-testrun-CMD    = test specific command CMD with '$(TEST.cmd.hosts)'
HELP-testrun-CMD.log = same as testrun-CMD but store output in '$(TEST.logdir)/'
HELP-_cmd3          = __________________________________________ special targets _
HELP-testcmd-cmd+ignored-keys = special target using commands which return random values

HELP.cmd            = $(_NL)\
\# Targets can be executed individually, or a group of targets can be executed$(_NL)\
\# by using the pattern rule  test.pattern-%  (see Makefile).$(_NL)\
\# Examples to execute individual targets:$(_NL)\
\#    $(MAKE_COMMAND) testcmd-cmd+info_localhost$(_NL)\
\#    $(MAKE_COMMAND) testcmd-cmd_vuln+BEAST_localhost$(_NL)\
\#    $(MAKE_COMMAND) testrun-+cn$(_NL)\
\# Examples to execute group of similar targets:$(_NL)\
\#    $(MAKE_COMMAND) test.pattern-+info$(_NL)\
\#    $(MAKE_COMMAND) test.pattern-+check$(_NL)\
\#    $(MAKE_COMMAND) test.pattern-+summ$(_NL)\
\#    $(MAKE_COMMAND) test.pattern-+vuln$(_NL)\
\#$(_NL)\
\# Some of the examples above use  localhost  as hostname by default.

HELP.test.cmd.all   = # no special documentation yet

# SEE Make:--ignore-output
LIST.ignore-output-keys := master_key \
			   session_id session_id_ctx \
			   session_startdate session_starttime \
			   session_ticket sts_expired
LIST.no-out.opt    := $(LIST.ignore-output-keys:%=--no-out=%)
LIST.ignore.cmd    := $(LIST.ignore-output-keys:%=+%)
# The  ignored keys are tested with the target  testcmd-cmd+ignored-keys_ .

# SEE Make:target name
# SEE Make:target name prefix

testcmd-cmd%:                   EXE.pl      = ../$(SRC.pl)
testcmd-cmd%:                   TEST.init   = --trace-CLI --header

testcmd-cmd-+ignored-keys_%:    TEST.args  += $(LIST.ignore.cmd)
testcmd-cmd-+info-_%:           TEST.args  += +info               $(LIST.no-out.opt)
testcmd-cmd-+info--tracecmd_%:  TEST.args  += +info  --trace-cmd  $(LIST.no-out.opt)
testcmd-cmd-+info--tracekey_%:  TEST.args  += +info  --trace-key  $(LIST.no-out.opt)
testcmd-cmd-+info--tracetime_%: TEST.args  += +info  --trace-time $(LIST.no-out.opt)
testcmd-cmd-+info--tracekey-norc_%: TEST.args += +info --trace-key --norc $(LIST.no-out.opt)
testcmd-cmd-+check_%:           TEST.args  += +check              $(LIST.no-out.opt)
testcmd-cmd-+check--nossltls_%: TEST.args  += +check --nosslv2 --nosslv3 --notlsv1 --notlsv11 --notlsv12 --notlsv13 $(LIST.no-out.opt)
    #    simulates a server not responding to ciphers
testcmd-cmd-+check--tracekey_%:     TEST.args  += +check --trace-key  $(LIST.no-out.opt)
testcmd-cmd-+check--tracetime_%:    TEST.args  += +check --trace-time $(LIST.no-out.opt)
testcmd-cmd-+check--tracenorc_%:    TEST.args  += +check --trace-cmd --norc --trace-time --trace=2 $(LIST.no-out.opt)
testcmd-cmd-+check--tracekey-norc_%: TEST.args += +check --trace-key --norc $(LIST.no-out.opt)
testcmd-cmd_vuln+BEAST_%:       TEST.args  += +BEAST
testcmd-cmd_vuln+CRIME_%:       TEST.args  += +CRIME
testcmd-cmd_vuln+DROWN_%:       TEST.args  += +DROWN
testcmd-cmd_vuln+FREAK_%:       TEST.args  += +FREAK
testcmd-cmd_vuln+POODLE_%:      TEST.args  += +POODLE
testcmd-cmd_vuln+logjam_%:      TEST.args  += +logjam
testcmd-cmd_vuln+lucky13_%:     TEST.args  += +lucky13
testcmd-cmd_vuln+Sloth_%:       TEST.args  += +Sloth
testcmd-cmd_vuln+Sweet32_%:     TEST.args  += +Sweet32
testcmd-cmd_summ+bsi_%:         TEST.args  += +bsi
testcmd-cmd_summ+TR-02102+_%:   TEST.args  += +TR-02102+
testcmd-cmd_summ+EV_%:          TEST.args  += +EV
testcmd-cmd_summ+quick_%:       TEST.args  += +quick --trace-arg
testcmd-cmd_summ+ocsp_%:        TEST.args  += +ocsp
testcmd-cmd_summ+preload_%:     TEST.args  += +preload
testcmd-cmd_summ+protocols_%:   TEST.args  += +protocols
testcmd-cmd_summ+fingerprints_%: TEST.args += +fingerprints
testcmd-cmd_summ+sizes_%:       TEST.args  += +sizes
testcmd-cmd_summ+pfs_%:         TEST.args  += +pfs
testcmd-cmd_summ+sni_%:         TEST.args  += +sni
testcmd-cmd_summ+vulns_%:       TEST.args  += +vulns
testcmd-cmd_summ+http_%:        TEST.args  += +http  $(LIST.no-out.opt)
testcmd-cmd_summ+hsts_%:        TEST.args  += +hsts  $(LIST.no-out.opt)
testcmd-cmd_summ+sts_%:         TEST.args  += +sts   $(LIST.no-out.opt)

testarg-cmd-host_url+cn:        TEST.args  += --v +cn
testarg-cmd-host_url+cn:        TEST.init   = localhost/tests
    # target to test hostname with url (path)

# SEE Make:target matching
# NOTE: no sort because we want the sequence of target definitions above.
ALL.testcmd         = $(shell awk -F% '($$1 ~ /^testcmd-cmd./){arr[$$1]=1}$(_AWK_print_arr_END)' $(_MYSELF.cmd))
ALL.test.cmd        = $(foreach host,$(TEST.cmd.hosts),$(ALL.testcmd:%=%$(host)))
ALL.test.cmd       += testarg-cmd-host_url+cn
ALL.test.cmd.log   += $(ALL.test.cmd:%=%.log)

# For calling various targets together and other examples,
# see  test.pattern-%  pattern rule

# testrun target to allow something like:  testrun-+my-fancy-command
# NOTE: testrun-+%  and not  testrun+%  is used to avoid double definition of
# the pattern rule (problem in GNU Make), this restricts the usage to pattern
# starting with  + , unfortunately.
# EXE.pl  and  TEST.init  will be inherited from  testcmd-cmd% .
testrun-+%:     TEST.args  += $(TEST.cmd.hosts)
testrun-%: testcmd-%
	@$(TRACE.target)

# TODO: implement following
#     $(MAKE_COMMAND) testrun-+cn\ --traceCMD
#     $(MAKE_COMMAND) testrun-'+cn --traceCMD'

# TODO: use target _no-hosts

test.cmd.log-compare:   TEST.target_prefix  = testcmd-cmd
test.cmd.log-move:      TEST.target_prefix  = testcmd-cmd
test.cmd.log:           TEST.target_prefix  = testcmd-cmd

test.cmd:           $(ALL.test.cmd)
test.cmd.log:       $(ALL.test.cmd.log) test.log-compare-hint
