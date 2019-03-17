#! /usr/bin/make -rRf
#?
#? NAME
#?      Makefile        - makefile for testing o-saft.cgi
#?
#? SYNOPSYS
#?      make [options] [target] [...]
#?
#? DESCRIPTION
#?      Makefile to perform testing tasks for o-saft.cgi .
#?
#? LIMITATIONS
#?      Requires GNU Make > 2.0.
#?
# HACKER's INFO
#       For details please see
#           ../Makefile  Makefile.help  Makefile.template
#
#? VERSION
#?      @(#) Makefile.cgi 1.24 19/03/17 23:18:33
#?
#? AUTHOR
#?      18-apr-18 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

_SID.cgi        = 1.24

_MYSELF.cgi     = t/Makefile.cgi
ALL.includes   += $(_MYSELF.cgi)
ALL.inc.type   += cgi

first-cgi-target-is-default: help.test.cgi

ALL.help.test  += help.test.cgi

HELP-help.test.cgi  = print targets for testing '$(SRC.cgi)'
help.test.cgi:      _HELP_TYP__ = cgi
help.test.cgi-v:    _HELP_TYP__ = cgi
help.test.cgi-vv:   _HELP_TYP__ = cgi

TEST.init       =

ifeq (,$(_SID.test))
    -include t/Makefile
endif

TEST.cgi.hosts      = localhost
ifdef TEST.hosts
    TEST.cgi.hosts  = $(TEST.hosts)
endif

MAKEFLAGS          += --no-print-directory
    # needed here, even if set in Makefile.inc; reason yet unknown (01/2019)


HELP-_cgi0              = _____________________________________________ testing .cgi _
HELP-test.cgi.all       = test all bad IPs, hostnames and options for '$(SRC.cgi)'
HELP-test.cgi.log       = same as test.cgi.all but store output in '$(TEST.logdir)/'
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
\#    $(MAKE_COMMAND) e-test.cgi.badhosts$(_NL)\
\#    $(MAKE_COMMAND) s-test.cgi.badIPs$(_NL)\
\#    $(MAKE_COMMAND) s-test.cgi.badopt$(_NL)\
\#$(_NL)\
\# There are no  test.cgi.*.log targets, please use  test.cgi.log  instead.$(_NL)\
\#$(_NL)\
\# Hint: use  test.pattern-cgi-  instead of  test.pattern-cgi , as the$(_NL)\
\#       patttern  cgi  may match other targets too.

#_____________________________________________________________________________
#________________________________________________________________ variables __|

# keep in mind: the targets should succeed for all hostnames and IPs

test.cgi.badhosts   = \
	hostname.ok.to.show.failed-status \
	localhost     any.local

# range from - - - - - - - - - - - - - - - - - - to
test.cgi.badIPv4    = \
	0.0.0.1                                  0.0.0.255 \
	10.0.0.1      10.0.0.255   10.12.34.56   10.255.255.255 \
	100.64.0.0                               100.64.0.255 \
	127.0.0.1     127.1.0.1                  127.1.0.255  \
	127.251.251.1                            127.255.255.255 \
	169.254.0.1   169.254.1.1                169.254.255.255 \
	172.16.0.1                               172.19.255.255  \
	192.0.0.1                                192.0.0.255 \
	192.0.2.1                                192.0.2.255 \
	192.88.99.1                              192.88.99.255 \
	192.168.0.1                              192.168.255.255 \
	198.18.0.1    198.18.0.255  198.18.1.1   198.18.0.1.255  \
	198.51.100.1                             198.51.100.255  \
	203.0.13.1                               203.0.13.255 \
	224.0.0.1     224.0.0.255   239.1.1.255  239.255.255.255 \
	240.0.0.1     251.251.251.251            255.255.255.255 \

# The IP or hostname becomes part of the target name, hence IPv6 are not
# possible verbatim because they contain : in the name; the : must be escaped
test.cgi.badIPv6    = \
	\:\:1         ffff\:\:1  7f00\:1          ffff\:7f00\:1 \
	ff02\:\:1     ff02\:\:fb \

# TODO: ff01::1 ff02::1
# TODO: fe80:21ab:22cd:2323::1 fec0:21ab:22cd:2323::1 feff:21ab:22cd:2323::1
#       fc00:21ab:22cd:2323::1 fdff:21ab:22cd:2323::1

HELP.cgi.internal   = "\
\# test.cgi.badhosts: $(test.cgi.badhosts)$(_NL)\
\# test.cgi.badIPs:   $(test.cgi.badIPs)$(_NL)\
\# test.cgi.goodIPs:  $(test.cgi.goodIPs)$(_NL)\
"

# TODO: *goodIP*  not yet ready
test.cgi.goodIPv4   =

test.cgi.goodIPv6   = \
	2002\:0\:0\:0\:0\:0\:b0b\:b0b \

test.cgi.badIPs     = $(test.cgi.badIPv4)  $(test.cgi.badIPv6)
test.cgi.goodIPs    = $(test.cgi.goodIPv4) $(test.cgi.goodIPv6)

ALL.cgi.badhosts    = $(test.cgi.badhosts:%=testcmd-cgi-bad_%)
ALL.cgi.badIPs      = $(test.cgi.badIPs:%=testcmd-cgi-bad_%)
ALL.cgi.goodIPs     = $(test.cgi.goodIPs:%=testcmd-cgi-good_%)

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

# Testing usage of --cgi  option; means that _args.cgi must be set explicitly.
# Test fails, if it reports something containing  exit=BEGIN0
testcmd-cgi--cgi_%:         _args.cgi   = --cgi --ok.to.show.failed-status +quit --exit=BEGIN0
testcmd-cgi--cgi-miss_%:    _args.cgi   = --missing--cgi +quit --exit=BEGIN0
testcmd-cgi--cgi-bad1_%:    _args.cgi   = --cgiwrong     +quit --exit=BEGIN0
testcmd-cgi--cgi-bad2_%:    _args.cgi   = --cgi=wrong    +quit --exit=BEGIN0
testcmd-cgi--cgi-bad3_%:    _args.cgi   = --wrongcgi     +quit --exit=BEGIN0

# all tests for good or bad arguments need the same initial options
_args.cgi   = --cgi +quit --exit=BEGIN0
testcmd-cgi-%:              EXE.pl      = ../$(SRC.cgi)
testcmd-cgi-bad%:           EXE.pl      = ../$(SRC.cgi)
testcmd-cgi-good%:          EXE.pl      = ../$(SRC.cgi)

# some characters are enclosed in _ and _ for better readability
testcmd-cgi-opt--opt_%:     _args.cgi  += --opt=ok.to.show.failed-status
testcmd-cgi-opt--cmd_%:     _args.cgi  += --cmd=list
testcmd-cgi-opt--env_%:     _args.cgi  += --env=not-allowed
testcmd-cgi-opt--exe_%:     _args.cgi  += --exe=not-allowed
testcmd-cgi-opt--lib_%:     _args.cgi  += --lib=not-allowed
testcmd-cgi-opt--cal_%:     _args.cgi  += --call=not-allowed
testcmd-cgi-opt--ssl_%:     _args.cgi  += --openssl=not-allowed
testcmd-cgi-chr-langle_%:   _args.cgi  += '--bad-char=_<_'
testcmd-cgi-chr-rangle_%:   _args.cgi  += '--bad-char=_>_'
testcmd-cgi-chr-semikolon_%:_args.cgi  += '--bad-char=_;_'
testcmd-cgi-chr-tilde_%:    _args.cgi  += '--bad-char=_~_'
testcmd-cgi-chr-question_%: _args.cgi  += '--bad-char=_?_'
#testcmd-cgi-chr-dollar_%:  _args.cgi  += '--bad-char=_\$$_'
testcmd-cgi-chr-percent_%:  _args.cgi  += '--bad-char=_%_'
testcmd-cgi-chr-dqoute_%:   _args.cgi  += '--bad-char=_\"_'
testcmd-cgi-chr-back_%:     _args.cgi  += '--bad-char=_\`_'
testcmd-cgi-chr-star_%:     _args.cgi  += '--bad-char=_*_'
testcmd-cgi-chr-lbrac_%:    _args.cgi  += '--bad-char=_(_'
testcmd-cgi-chr-rbrac_%:    _args.cgi  += '--bad-char=_)_'
testcmd-cgi-chr-lsquare_%:  _args.cgi  += '--bad-char=_[_'
testcmd-cgi-chr-rsquare_%:  _args.cgi  += '--bad-char=_]_'
testcmd-cgi-chr-lcurl_%:    _args.cgi  += '--bad-char=_{_'
testcmd-cgi-chr-rcurl_%:    _args.cgi  += '--bad-char=_}_'
testcmd-cgi-chr-caret_%:    _args.cgi  += '--bad-char=_^_'
testcmd-cgi-chr-bar_%:      _args.cgi  += '--bad-char=_|_'
testcmd-cgi-chr-hash_%:     _args.cgi  += '--bad-char=_\#_'

testcmd-cgi-%:
	@$(TRACE.target)
	@$(eval _host := $(shell echo "$*" | awk -F_ '{print $$NF}'))
	@$(MAKE) $(MFLAGS) -i no.message-exit.BEGIN0 EXE.pl=$(EXE.pl) TEST.args="$(_args.cgi) --host=$(_host)"

# TODO: following target prints "#o-saft.pl..."
testcmd-cgi-good%:
	@$(TRACE.target)
	@$(eval _host := $(shell echo "$*" | awk -F_ '{print $$NF}'))
	@$(MAKE) $(MFLAGS) -i    message-exit.BEGIN0 EXE.pl=$(EXE.pl) TEST.args="$(_args.cgi) --host=$(_host)"

# alias for simple usage
test.cgi-%: testcmd-cgi-bad_%
	@echo ""

ALL.testcgiopt  = $(shell awk -F% '/^testcmd-cgi-opt-/ {arr[$$1]=1}$(_AWK_print_arr_END)' $(_MYSELF.cgi))
ALL.testcgichr  = $(shell awk -F% '/^testcmd-cgi-chr-/ {arr[$$1]=1}$(_AWK_print_arr_END)' $(_MYSELF.cgi))
ALL.cgi.badchr  = $(ALL.testcgichr:%=%any.FQDN)
ALL.cgi.badopt  = $(ALL.testcgiopt:%=%any.FQDN)
ALL.testcgi     = $(ALL.testcgiopt)
ALL.test.cgi    = $(ALL.cgi.badopt) $(ALL.cgi.badchr) $(ALL.cgi.badhosts) $(ALL.cgi.badIPs) $(ALL.cgi.goodIPs)

test.cgi.badhosts: $(ALL.cgi.badhosts)
test.cgi.badIPs:   $(ALL.cgi.badIPs)
test.cgi.badall:   test.cgi.badhosts test.cgi.badIPs
test.cgi.badopt:   $(ALL.cgi.badopt)
test.cgi.badchr:   $(ALL.cgi.badchr)
test.cgi.goodIPs:  $(ALL.cgi.goodIPs)

test.cgi.all:      $(ALL.test.cgi)
test.cgi:          $(ALL.test.cgi)

_TEST.CGI.log   = $(TEST.logdir)/test.cgi.log-$(_TODAY_)
# use 'make -i ...' because we have targets which fail, which is intended
$(_TEST.CGI.log):
	@echo "# Makefile.cgi 1.24: $(MAKE) test.cgi.log" > $@
	@$(MAKE) -i test.cgi >> $@ 2>&1

test.cgi.log: $(_TEST.CGI.log)
	@$(TRACE.target)
	@$(TRACE.target.log)
	@diff $(TEST.logdir)/$@ $(_TEST.CGI.log) \
	    && rm $(_TEST.CGI.log) \
	    || mv $(_TEST.CGI.log) $(TEST.logdir)/$@
	@-test -f $(TEST.logdir)/$@  ||  mv $(_TEST.CGI.log) $(TEST.logdir)/$@
	@ls -l  $(TEST.logdir)/$@*
# TODO: same target as test.warnings.log
ALL.tests.cgi.log  += $(test.cgi.log)

.PHONY: test.cgi.log

#_____________________________________________________________________________ 
#_____________________________________________________________________ test __|

# feed main Makefile
ALL.tests      += $(ALL.test.cgi)
ALL.tests.log  += $(ALL.test.cgi.log)
