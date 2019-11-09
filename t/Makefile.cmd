#! /usr/bin/make -rRf
#?
#? DESCRIPTION
#?      For more details please see
#?          ../Makefile  Makefile  Makefile.help  Makefile.pod
#?      make help.test.cmd
#?
#? VERSION
#?      @(#) Makefile.cmd 1.41 19/11/09 19:43:18
#?
#? AUTHOR
#?      18-apr-18 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

HELP-help.test.cmd := targets for testing '$(SRC.pl)' commands and options

_SID.cmd           := 1.41

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
HELP-test.cmd.all   = test all commands with '$(TEST.cmd.hosts)'
HELP-test.cmd.log   = same as test.cmd.all but store output in '$(TEST.logdir)/'
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
\#    $(MAKE_COMMAND) testcmd-cmd+cipher--cipher-alpn_localhost$(_NL)\
\#    $(MAKE_COMMAND) testrun-+cn$(_NL)\
\# Examples to execute group of similar targets:$(_NL)\
\#    $(MAKE_COMMAND) test.pattern-+info$(_NL)\
\#    $(MAKE_COMMAND) test.pattern-+check$(_NL)\
\#    $(MAKE_COMMAND) test.pattern-+cipher$(_NL)\
\#    $(MAKE_COMMAND) test.pattern-+summ$(_NL)\
\#    $(MAKE_COMMAND) test.pattern-+vuln$(_NL)\
\# All following examples are the same:$(_NL)\
\#    $(MAKE_COMMAND) testrun-+cipher TEST.init='--header --enabled'$(_NL)\
\#    $(MAKE_COMMAND) testcmd-+cipher TEST.init='--header --enabled localhost'$(_NL)\
\#    $(MAKE_COMMAND) testcmd-+cipher TEST.args='--header --enabled localhost'$(_NL)\
\#$(_NL)\
\# Some of the examples above use  localhost  as hostname by default.

HELP.test.cmd.all   = # no special documentation yet

# Some values of keys are different by nature for each call of  o-saft.pl .
# These keys (commands) should be ignored for all  +info and +check  targets
# to avoid diffs when testing (i.e. with  *.log  targets).  To ignore output
# for the keys, the option  --no-out= is used (alias for  --ignore-output=).
# but keeps the command line shorter).
# The  ignored keys are tested with the target  testcmd-cmd+ignored-keys_
_ignore-output-keys := master_key \
		      session_id session_id_ctx \
		      session_startdate session_starttime \
		      session_ticket sts_expired
_ignore-output     := $(_ignore-output-keys:%=--no-out=%)
_ignore-output-cmd := $(_ignore-output-keys:%=+%)

# SEE Make:target name
# SEE Make:target name prefix

testcmd-cmd%:                   EXE.pl      = ../$(SRC.pl)
testcmd-cmd%:                   TEST.init   = --trace-CLI --header

testcmd-cmd+ignored-keys_%:     TEST.args  += $(_ignore-output-cmd)
testcmd-cmd+info-_%:            TEST.args  += +info               $(_ignore-output) 
testcmd-cmd+info--trace-cmd_%:  TEST.args  += +info  --trace-cmd  $(_ignore-output) 
testcmd-cmd+info--trace-key_%:  TEST.args  += +info  --trace-key  $(_ignore-output) 
testcmd-cmd+info--trace-time_%: TEST.args  += +info  --trace-time $(_ignore-output) 
testcmd-cmd+info--trace-key-norc_%: TEST.args  += +info   --trace-key --norc $(_ignore-output)
testcmd-cmd+check_%:            TEST.args  += +check              $(_ignore-output)
testcmd-cmd+check--nossltls_%:  TEST.args  += +check --nosslv2 --nosslv3 --notlsv1 --notlsv11 --notlsv12 --notlsv13 $(_ignore-output) 
    #    simulates a server not responding to ciphers
testcmd-cmd+check--trace-key_%: TEST.args  += +check --trace-key  $(_ignore-output) 
testcmd-cmd+check--trace-time_%:    TEST.args  += +check --trace-time $(_ignore-output) 
testcmd-cmd+check--trace-norc_%:    TEST.args  += +check --trace-cmd --trace-time --trace=2 --norc $(_ignore-output) 
testcmd-cmd+check--trace-key-norc_%:  TEST.args  += +check  --trace-key --norc $(_ignore-output) 
testcmd-cmd+cipher-_%:                TEST.args  += +cipher
testcmd-cmd+cipher--legacy-owasp_%:   TEST.args  += +cipher --legacy=owasp
testcmd-cmd+cipher--force-openssl_%:  TEST.args  += +cipher --force-openssl
testcmd-cmd+cipher--cipher-openssl_%: TEST.args  += +cipher --cipher-openssl
testcmd-cmd+cipher--cipher-alpn_%:    TEST.args  += +cipher --cipher-alpn
testcmd-cmd+cipher--cipher-npn_%:     TEST.args  += +cipher --cipher-npn
testcmd-cmd+cipher--cipher-curves_%:  TEST.args  += +cipher --cipher-curves
#TODO: testcmd-cmd+cipher--cipher-npns-%:  TEST.args  += +cipher --cipher-npns=,
#TODO: testcmd-cmd+cipher--cipher-npns-%:  TEST.args  += +cipher --cipher-npns=, --cipher-npns=,,
#TODO: testcmd-cmd+cipher--cipher-npns-%:  TEST.args  += +cipher --cipher-npns=, --cipher-npns=ecdh_x448
testcmd-cmd+cipherall_%:        TEST.args  += +cipherall
testcmd-cmd+cipherraw_%:        TEST.args  += +cipherraw
testcmd-cmd+cipher-dh_%:        TEST.args  += +cipher-dh
testcmd-cmd+cipher-default_%:   TEST.args  += +cipher-default
testcmd-cmd+ciphercheck_%:      TEST.args  += +ciphercheck
testcmd-cmd+cipher--nossltls_%: TEST.args  += +cipher --nosslv2 --nosslv3 --notlsv1 --notlsv11 --notlsv12 --notlsv13
    #    simulates a server not responding to ciphers
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
testcmd-cmd_summ+http_%:        TEST.args  += +http  --no-out=sts_expired
testcmd-cmd_summ+hsts_%:        TEST.args  += +hsts  --no-out=sts_expired
testcmd-cmd_summ+sts_%:         TEST.args  += +sts   --no-out=sts_expired
    # --no-out=sts_expired  to avoid diffs when testing

test.cmd.log-compare:   TEST.target_prefix  = testcmd-cmd
test.cmd.log-move:      TEST.target_prefix  = testcmd-cmd
test.cmd.log:           TEST.target_prefix  = testcmd-cmd

# SEE Make:target matching
# NOTE: no sort because we want the sequence of target definitions above.
ALL.testcmd     = $(shell awk -F% '($$1 ~ /^testcmd-cmd./){arr[$$1]=1}$(_AWK_print_arr_END)' $(_MYSELF.cmd))
ALL.test.cmd    = $(foreach host,$(TEST.cmd.hosts),$(ALL.testcmd:%=%$(host)))
ALL.test.cmd.log  += $(ALL.test.cmd:%=%.log)

test.cmd.all:   $(ALL.test.cmd)
test.cmd:       test.cmd.all
test.cmd.log:   $(ALL.test.cmd.log) test.log-compare-hint

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
#     $(MAKE_COMMAND) testrun-'+cipher --enabled'

# TODO: use target _no-hosts

#_____________________________________________________________________________
#_____________________________________________________________________ test __|

# feed main Makefile
ALL.tests      += $(ALL.test.cmd)
ALL.tests.log  += $(ALL.test.cmd.log)

