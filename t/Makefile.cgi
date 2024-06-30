#!/usr/bin/make -rRf
#?
#? DESCRIPTION
#?      For more details please see
#?          ../Makefile  Makefile  Makefile.help  Makefile.pod
#?      make help.test.cgi
#?
#? VERSION
#?      @(#) Makefile.cgi 3.2 24/06/30 19:15:57
#?
#? AUTHOR
#?      18-apr-18 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

HELP-help.test.cgi  = targets for testing '$(SRC.cgi)' (mainly invalid arguments)

_SID.cgi           := 3.2

_MYSELF.cgi        := t/Makefile.cgi
ALL.includes       += $(_MYSELF.cgi)
ALL.inc.type       += cgi
ALL.help.tests     += help.test.cgi

first-cgi-target-is-default: help.test.cgi

ifeq (,$(_SID.test))
    -include t/Makefile
endif

TEST.cgi.hosts      =
ifdef TEST.hosts
    TEST.cgi.hosts  = $(TEST.hosts)
endif

MAKEFLAGS          += --no-print-directory
    # needed here, even if set in Makefile.inc; reason yet unknown (01/2019)

help.test.cgi:        HELP_TYPE = cgi
help.test.cgi-v:      HELP_TYPE = cgi
help.test.cgi-vv:     HELP_TYPE = cgi

HELP-_cgi0              = _____________________________________________ testing .cgi _
HELP-test.cgi           = test all bad IPs, hostnames and options for '$(SRC.cgi)'
HELP-test.cgi.log       = same as test.cgi but store output in '$(TEST.logdir)/'
HELP-test.cgi.badhosts  = test that some hostnames are ignored in '$(SRC.cgi)'
HELP-test.cgi.badIPs    = test that some IPs are ignored in '$(SRC.cgi)'
HELP-test.cgi.badall    = test all bad and good IPs and hostnames
HELP-test.cgi.badopt    = test bad options and characters
HELP-test.cgi.goodIPs   = test IPs to be passed
HELP-test.cgi-NAME      = same as testcmd-cgi-bad_NAME
HELP-testcmd-cgi-bad_NAME = check if a single NAME (IP or hostname) allowed in '$(SRC.cgi)'

HELP.cgi                = $(_NL)\
\# Examples: $(_NL)\
\#    $(MAKE_COMMAND) test.cgiall$(_NL)\
\#    $(MAKE_COMMAND) testcmd-cgi-bad_42.42.42.42$(_NL)\
\#    $(MAKE_COMMAND) testcmd-cgi-bad_127.0.0.127$(_NL)\
\#    $(MAKE_COMMAND) testcmd-cgi-bad_localhost$(_NL)\
\#    $(MAKE_COMMAND) e-LIST.cgi.badhosts$(_NL)\
\#    $(MAKE_COMMAND) s-LIST.cgi.badIPs$(_NL)\
\#    $(MAKE_COMMAND) s-LIST.cgi.badopt$(_NL)\
\#$(_NL)\
\# There are no  test.cgi.*.log targets, please use  test.cgi.log  instead.$(_NL)\
\#$(_NL)\
\# Hint: use  test.pattern-cgi-  instead of  test.pattern-cgi , as the$(_NL)\
\#       patttern  cgi  may match other targets too.

LIST.cgi.badhosts  := \
	localhost     any.local
#	hostname.ok.to.show.failed-status 

# range from - - - - - - - - - - - - - - - - - - to
LIST.cgi.badIPv4   := \
	0.0.0.1                                  0.0.0.255       \
	10.0.0.1      10.0.0.255   10.12.34.56   10.255.255.255  \
	100.64.0.0                               100.64.0.255    \
	127.0.0.1     127.1.0.1                  127.1.0.255     \
	127.251.251.1                            127.255.255.255 \
	169.254.0.1   169.254.1.1                169.254.255.255 \
	172.16.0.1                               172.19.255.255  \
	192.0.0.1                                192.0.0.255     \
	192.0.2.1                                192.0.2.255     \
	192.88.99.1                              192.88.99.25    \
	192.168.0.1                              192.168.255.255 \
	198.18.0.1    198.18.0.255  198.18.1.1   198.18.0.1.255  \
	198.51.100.1                             198.51.100.255  \
	203.0.13.1                               203.0.13.255    \
	224.0.0.1     224.0.0.255   239.1.1.255  239.255.255.255 \
	240.0.0.1     251.251.251.251            255.255.255.255 \
	127.0.1       127.1         10.0.1  10.1 224.0.1   224.1 \
	127001        111111        2133465000   127.666   42    \
	0127.0.1      127.071       127.0.07     127.0.0.000042  \
	0x7f.0.1      0x0b.026.8492 127.0x71     127.0.0.000x42  \
	0x07f000001 \

# last line contain IPs with ocatl notations; should be ignored in general

# the IP or hostname becomes part of the target name, hence IPv6 are not
# possible verbatim because they contain : in the name; the : must be escaped
LIST.cgi.badIPv6   := \
	\:\:1         ffff\:\:1  7f00\:1          ffff\:7f00\:1 \
	ff01\:\:1     ff02\:\:1  ff02\:\:fb       64\:abcd\:\:  \
	\:251.1.1.1  \:\:251.1.1.1 \:abcd\:251.1.1.1 \:abcd\:\:251.1.1.1 \
        abcd\:\:251.1.1.1   abcd\:\:\:251.1.1.1   abcd\:a\:\:251.1.1.1 \
	fe80\:21ab\:22cd\:2323\:\:1 fec0\:21ab\:22cd\:2323\:\:1 feff\:21ab\:22cd\:2323\:\:1 \
	fc00\:21ab\:22cd\:2323\:\:1 fdff\:21ab\:22cd\:2323\:\:1 \

HELP.cgi.internal   = "\
\# test.cgi.badhosts: $(LIST.cgi.badhosts)$(_NL)\
\# test.cgi.badIPs:   $(LIST.cgi.badIPs)$(_NL)\
\# test.cgi.goodIPs:  $(LIST.cgi.goodIPs)$(_NL)\
"

# TODO: *goodIP*  not yet ready
LIST.cgi.goodhosts := localhost.ok
LIST.cgi.goodIPv4  := 

#	128.0.1       128.1         192.1        \

LIST.cgi.goodIPv6  := \
	ffff \
	2002\:0\:0\:0\:0\:0\:b0b\:b0b \
	fe00\:21ab\:22cd\:2323\:\:1

LIST.cgi.badIPs    := $(LIST.cgi.badIPv4)  $(LIST.cgi.badIPv6)
LIST.cgi.goodIPs   := $(LIST.cgi.goodIPv4) $(LIST.cgi.goodIPv6)

ALL.cgi.goodhosts  := $(LIST.cgi.goodhosts:%=testcmd-cgi-good_%)
ALL.cgi.goodIPs    := $(LIST.cgi.goodIPs:%=testcmd-cgi-good_%)
ALL.cgi.badhosts   := $(LIST.cgi.badhosts:%=testcmd-cgi-bad_%)
ALL.cgi.badIPs     := $(LIST.cgi.badIPs:%=testcmd-cgi-bad_%)

HELP.test.cgi.all   = $(_NL)\
\# targets for testing bad hosts:$(_NL)\
$(ALL.cgi.badhosts)$(_NL)\
$(_NL)\
\# targets for testing bad IPs:$(_NL)\
$(ALL.cgi.badIPs)$(_NL)\
$(_NL)\
\# targets for testing good IPs:$(_NL)\
$(ALL.cgi.goodIPs)$(_NL)\


# SEE Make:target name
# SEE Make:target name prefix

# Testing for invalid arguments, hostnames and IPs uses following command:
#       o-saft.cgi --cgi +quit --exit=BEGIN0 --host=10.0.0.1
# or
#       env QUERY_STRING="--cgi&--cmd=quit&--exit=BEGIN0&--host=10.0.0.1" o-saft.cgi
# they should return:
#       X-Cite: Perl is a mess. ...
#       X-O-Saft: OWASP – SSL advanced forensic tool
#       Content-type: text/plain; charset=utf-8
#       
#       #o-saft.pl  _yeast_EXIT exit=BEGIN0 - BEGIN start
#
# The option  --exit=BEGIN0  ensures that nothing will be done in o-saft.pl .
# It ensures that the last line of the output contains exit=BEGIN0 . This last
# line is missing if  o-saft.cgi  exits because  an invalid argument, hostname
# or IP  was detected. The purpose here is to check if o-saft.cgi exits, hence
# the test succeeds, if the last line is missing.
# The target no.message is used for each individual test. It is a pattern rule
# in t/Makefile and uses the variables  EXE.pl, TEST.args and TEST.INIT, which
# are passed as arguments to the recursive MAKE call.
# "make -i" is used to ensure that all tests are performed.

# testing usage of --cgi  option; means that  TEST.init must be set explicitly
# test fails, if it reports something containing  exit=BEGIN0

# All tests for good or bad arguments need the same initial options
testcmd-cgi-%:              EXE.pl      = ../$(SRC.cgi)
testcmd-cgi-bad%:           EXE.pl      = ../$(SRC.cgi)
testcmd-cgi-good%:          EXE.pl      = ../$(SRC.cgi)
test.cgi:                   TEST.init   = --cgi --exit=BEGIN0 +quit
testcmd-cgi-%:              TEST.init   = --cgi --exit=BEGIN0 +quit
testcmd-cgi-chr%:           TEST.init   = --cgi

testarg-cgi-%:              EXE.pl      = ../$(SRC.cgi)
testarg-cgi-%:              TEST.init   = --cgi --exit=BEGIN0 +quit
# check host argument without --host=
testarg-cgi-host-localhost: TEST.init  += localhost
testarg-cgi-host-127_42:    TEST.init  += 127.42
testarg-cgi-host-12742:     TEST.init  += 12742
testarg-cgi-host-2133465000: TEST.init += 2133465000
testarg-cgi-host-7f00_1:    TEST.init  += 7f00:1
testarg-cgi-host-ffff__1:   TEST.init  += ffff::1

ALL.cgi.badarg  = $(shell awk -F: '/^testarg-cgi-host-/ {arr[$$1]=1}$(_EXE.print_arr_END.awk)' $(_MYSELF.cgi))

# special targets to test bad --cgi
#testarg-cgi---cgi_ok:       TEST.init   = --cgi --ok.to.show.failed-status --exit=BEGIN0 +quit
testarg-cgi---cgi-miss:     TEST.init   = --missing--cgi --exit=BEGIN0 +quit
testarg-cgi---cgi-bad1:     TEST.init   = --cgiwrong     --exit=BEGIN0 +quit
testarg-cgi---cgi-bad2:     TEST.init   = --cgi=wrong    --exit=BEGIN0 +quit
testarg-cgi---cgi-bad3:     TEST.init   = --wrongcgi     --exit=BEGIN0 +quit

ALL.cgi.badcgi  = testarg-cgi---cgi-miss testarg-cgi---cgi-bad1 testarg-cgi---cgi-bad2 testarg-cgi---cgi-bad3

# arguments silently ignored by $(SRC.cgi), hence it will not die;
# target succeeds if $(SRC.cgi) returns exit=BEGIN0 0; hence testcmd-cgi-good-
LIST.cgi-opt-ignore := \
	--cmd=list         --cmd=+list --cmd=+dump     --url=+dump       \
	--traceARG         --trace     --cmd=--trace   --url=--trace     \
	                   --v         --cmd=--v       --url=--v         \
	--cmd=+version     --ca-file=not-allowed  --ca-path=not-allowed  \
	--cmd=libversion   --ca-files=not-allowed --ca-paths=not-allowed \
	--rc=not-allowed

# arguments checked by $(SRC.cgi), hence it will die;
# target succeeds if $(SRC.cgi) does not returns exit=BEGIN0
LIST.cgi-opt-die    := \
	--env=not-allowed  --exe=not-allowed      --lib=not-allowed  \
	--call=not-allowed --openssl=not-allowed 

ifndef cgi-targets-generated
    # SEE Make:macros
    $(foreach arg, $(LIST.cgi-opt-ignore), \
	$(eval _target=testcmd-cgi-good-$(subst =,-,$(arg))_any.FQDN) \
	$(eval $(_target):  TEST.init += $(arg)) \
	$(eval ALL.cgi.badopt += $(_target))     \
    )
    $(foreach arg, $(LIST.cgi-opt-die), $(eval \
	testcmd-cgi-$(subst =,-,$(arg))_any.FQDN:  TEST.init += $(arg) \
    ))
    $(foreach arg, $(LIST.cgi-opt-die), $(eval \
	ALL.cgi.badopt += testcmd-cgi-$(subst =,-,$(arg))_any.FQDN \
    ))
    undefine arg
    undefine _target
endif

# targets for bad characters are written literally because it is difficult
# to replace the character in the generated target name
# the bad characters are enclosed in _ and _ for better readability
testcmd-cgi-chr-langle_any.FQDN:   TEST.init  += '--bad-char=_<_'
testcmd-cgi-chr-rangle_any.FQDN:   TEST.init  += '--bad-char=_>_'
testcmd-cgi-chr-semikolon_any.FQDN:TEST.init  += '--bad-char=_;_'
testcmd-cgi-chr-tilde_any.FQDN:    TEST.init  += '--bad-char=_~_'
testcmd-cgi-chr-question_any.FQDN: TEST.init  += '--bad-char=_?_'
#testcmd-cgi-chr-dollar_any.FQDN:   TEST.init  += '--bad-char=_\$$_'
testcmd-cgi-chr-percent_any.FQDN:  TEST.init  += '--bad-char=_%_'
testcmd-cgi-chr-dqoute_any.FQDN:   TEST.init  += '--bad-char=_\"_'
testcmd-cgi-chr-back_any.FQDN:     TEST.init  += '--bad-char=_\`_'
testcmd-cgi-chr-star_any.FQDN:     TEST.init  += '--bad-char=_*_'
testcmd-cgi-chr-lbrac_any.FQDN:    TEST.init  += '--bad-char=_(_'
testcmd-cgi-chr-rbrac_any.FQDN:    TEST.init  += '--bad-char=_)_'
testcmd-cgi-chr-lsquare_any.FQDN:  TEST.init  += '--bad-char=_[_'
testcmd-cgi-chr-rsquare_any.FQDN:  TEST.init  += '--bad-char=_]_'
testcmd-cgi-chr-lcurl_any.FQDN:    TEST.init  += '--bad-char=_{_'
testcmd-cgi-chr-rcurl_any.FQDN:    TEST.init  += '--bad-char=_}_'
testcmd-cgi-chr-caret_any.FQDN:    TEST.init  += '--bad-char=_^_'
testcmd-cgi-chr-bar_any.FQDN:      TEST.init  += '--bad-char=_|_'
testcmd-cgi-chr-hash_any.FQDN:     TEST.init  += '--bad-char=_\#_'

ALL.cgi.badchr  = $(shell awk -F: '/^testcmd-cgi-chr-/ {arr[$$1]=1}$(_EXE.print_arr_END.awk)' $(_MYSELF.cgi))

# check HTTP header options
# NOTE: target name is testarg-cgi_ instead of testarg-cgi- because it should
#       not match pattern rule testarg-cgi-%
testarg-cgi_with%:          EXE.pl      = ../$(SRC.cgi)
testarg-cgi_with%:          TEST.init   =
testarg-cgi_with-header:    TEST.init  += --cgi --exit=ARGS --with_HTTP_header --cgi-header
testarg-cgi_without-header: TEST.init  += --cgi --exit=ARGS --with_HTTP_header --cgi-no-header

ALL.cgi.header  = testarg-cgi_with-header testarg-cgi_without-header

test.cgi.log-compare:   TEST.target_prefix  = testcmd-cgi
test.cgi.log-move:      TEST.target_prefix  = testcmd-cgi
    # TEST.target_prefix not yet used
    # FIXME: general rule can only handle on perfix, but we have testcmd- and testarg. here

# NOTE: --exit=BEGIN0 must not be the last argument, because it triggers buggy
#       check in o-saft.cgi (at least up to version 1.44), hence --dummy added
testarg-cgi-%:
	@$(O-TRACE.target)
	@$(MAKE) $(MFLAGS) no.message-exit.BEGIN0 EXE.pl=$(EXE.pl) TEST.init="$(TEST.init)" TEST.args=--dummy

testcmd-cgi-%:
	@$(O-TRACE.target)
	@$(eval _host := $(shell echo "$*" | awk -F_ '{print $$NF}'))
	@$(MAKE) $(MFLAGS) no.message-exit.BEGIN0 EXE.pl=$(EXE.pl) TEST.init="$(TEST.init) --host=$(_host)" TEST.args=--dummy

# TODO: following target prints "#o-saft.pl..."
testcmd-cgi-good%:
	@$(O-TRACE.target)
	@$(eval _host := $(shell echo "$*" | awk -F_ '{print $$NF}'))
	@$(MAKE) $(MFLAGS)    message-exit.BEGIN0 EXE.pl=$(EXE.pl) TEST.init="$(TEST.init) --host=$(_host)" TEST.args=--dummy

# alias for simple usage
test.cgi-%: testcmd-cgi-bad_%
	@echo ""

ALL.test.cgi    = \
	$(ALL.cgi.goodhosts) \
	$(ALL.cgi.goodIPs) \
	$(ALL.cgi.badopt) \
	$(ALL.cgi.badchr) \
	$(ALL.cgi.badhosts) \
	$(ALL.cgi.badIPs) \
	$(ALL.cgi.badarg) \
	$(ALL.cgi.badcgi) \
	$(ALL.cgi.header)

test.cgi.badhosts: $(ALL.cgi.badhosts)
test.cgi.badIPs:   $(ALL.cgi.badIPs)
test.cgi.badall:   test.cgi.badhosts test.cgi.badIPs
test.cgi.badopt:   $(ALL.cgi.badopt)
test.cgi.badchr:   $(ALL.cgi.badchr)
test.cgi.goodIPs:  $(ALL.cgi.goodIPs)
test.cgi.goodhosts:$(ALL.cgi.goodhosts)

_TEST.cgi.log   = $(TEST.logdir)/test.cgi.log-$(TEST.today)
# use 'make -i ...' because we have targets which fail, which is intended
$(_TEST.cgi.log):
	@echo "# Makefile.cgi 3.2: $(MAKE) test.cgi.log" > $@
	@$(MAKE) -i test.cgi >> $@ 2>&1

# not yet needed: test.log-compare-hint
test.cgi.log: $(_TEST.cgi.log) $(ALL.cgi.header:%=%.log)
	@$(O-TRACE.target)
	@$(O-TRACE.target.log)
	@diff $(TEST.logdir)/$@ $(_TEST.cgi.log) \
	    && rm $(_TEST.cgi.log) \
	    || mv $(_TEST.cgi.log) $(TEST.logdir)/$@
	@-test -f $(TEST.logdir)/$@  ||  mv $(_TEST.cgi.log) $(TEST.logdir)/$@
	@ls -l  $(TEST.logdir)/$@*
# TODO: same target as test.warnings.log
ALL.test.cgi.log   += test.cgi.log

ifndef ALL.Makefiles
# NOTE: needed if called with -f Makefile.cgi
%-v: O-TRACE.target = echo "\# $@: $?"
%-v: %
	echo CGI $(TEST.init)
	@$(EXE.dummy)

%-vv: O-TRACE.target= echo "\# $@: $^"
%-vv: %
	echo CGI
	@$(EXE.dummy)
endif

test.cgi:           $(ALL.test.cgi)
