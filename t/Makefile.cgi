#! /usr/bin/make -rRf
#?
#? NAME
#?      Makefile    - makefile for testing o-saft.cgi
#?
#? SYNOPSYS
#?      make [options] [target] [...]
#?
#? DESCRIPTION
#?      Makefile to perform testing tasks for o-saft.cgi
#?
#? LIMITATIONS
#?      Requires GNU Make > 2.0.
#?
# HACKER's INFO
#       For details please see
#           ../Makefile  ../Makefile.help  Makefile.template
#
#       TODO:
#          * complete with tests from t/test-o-saft.cgi.sh
#
#? VERSION
#?      @(#) Makefile.cgi 1.11 18/08/10 00:08:10
#?
#? AUTHOR
#?      18-apr-18 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

_SID.cgi        = 1.11

_MYSELF.cgi     = t/Makefile.cgi
ALL.includes   += $(_MYSELF.cgi)

MAKEFLAGS      += --no-builtin-variables --no-builtin-rules --no-print-directory
.SUFFIXES:

first-cgi-target-is-default: help.test.cgi

ifeq (,$(_SID.test))
    -include t/Makefile
endif

TEST.cgi.hosts      = localhost
ifdef TEST.hosts
    TEST.cgi.hosts  = $(TEST.hosts)
endif

MORE-cgi        = " \
\#               ___________________________________________ testing .cgi _$(_NL)\
 test.cgi            - test all bad IPs, hostnames and options for $(SRC.cgi) $(_NL)\
 test.cgi.log        - same as test.cgi but store output in $(TEST.logdir)/ $(_NL)\
 test.cgi.badhosts   - test that some hostnames are ignored in $(SRC.cgi) $(_NL)\
 test.cgi.badIPs     - test that some IPs are ignored in $(SRC.cgi) $(_NL)\
 test.cgi.badall     - test all bad and good IPs and hostnames $(_NL)\
 test.cgi.badopt     - test bad options and characters$(_NL)\
 test.badhost-NAME   - check a single NAME (IP or hostname) if allowed in $(SRC.cgi) $(_NL)\
\#$(_NL)\
\# Examples: $(_NL)\
\#    make test.cgi $(_NL)\
\#    make test.cgibad_42.42.42.42 $(_NL)\
\#    make test.cgibad_127.0.0.127 $(_NL)\
\#    make test.cgibad_localhost   $(_NL)\
\#    make e-test.cgi.badhosts $(_NL)\
\#    make s-test.cgi.badIPs $(_NL)\
\#    make s-test.cgi.badopt $(_NL)\
\#$(_NL)\
\# there are no  test.cgi.*.log targets, please use  test.cgi.log  instead $(_NL)\
"

HELP-help.test.cgi  = print targets for testing $(SRC.cgi)
help.test.cgi:
	@echo " $(_HELP_LINE_)$(_NL) $(_HELP_INFO_)$(_NL) $(_HELP_LINE_)$(_NL)"
	@echo $(MORE-cgi)      ; # no quotes!

.PHONY: help.test.cgi

#_____________________________________________________________________________
#________________________________________________________________ variables __|

# keep in mind: the targets should succeed for all hostnames and IPs

test.cgi.badhosts   = \
	hostname.ok.to.show.failed-status \
	localhost 

# range from - - - - - - - - - - - - - - - - - - to
test.cgi.badIPv4    = \
	0.0.0.1                                  0.0.0.255 \
	10.0.0.1      10.0.0.255   10.12.34.56   10.255.255.255 \
	100.64.0.0                               100.64.0.255 \
	127.0.0.1     127.1.0.1                  127.1.0.255  \
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

# TODO: ff01::1 ff02::1
# TODO: fe80:21ab:22cd:2323::1 fec0:21ab:22cd:2323::1 feff:21ab:22cd:2323::1
#       fc00:21ab:22cd:2323::1 fdff:21ab:22cd:2323::1

test.cgi.badIPs     = $(test.cgi.badIPv4) $(test.cgi.badIPv6)

ALL.cgi.badhosts    = $(test.cgi.badhosts:%=test.cgibad_%)
ALL.cgi.badIPs      = $(test.cgi.badIPs:%=test.cgibad_%)


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
# or IPs was detected. The purpose here is to check if o-saft.cgi exits, hence
# The test succeeds, if the last line is missing.
# The target no.message is used for each individual test. It is a pattern rule
# in t/Makefile and uses the variables  EXE.pl, TEST.args and TEST.INIT, which
# are passed as arguments to the recursive MAKE call.
# "make -i" is used to ensure that all tests are performed.

# testing usage of --cgi  option; means that _cgi.args must be set explicitly
test.cgibad--cgi00_%: _cgi.args = --cgi --ok.to.show.failed-status +quit --exit=BEGIN0
test.cgibad--cgi01_%: _cgi.args = --missing--cgi +quit --exit=BEGIN0
test.cgibad--cgi02_%: _cgi.args = --cgiwrong     +quit --exit=BEGIN0
test.cgibad--cgi03_%: _cgi.args = --cgi=wrong    +quit --exit=BEGIN0
test.cgibad--cgi04_%: _cgi.args = --wrongcgi     +quit --exit=BEGIN0

# all tests for bad arguments need the same initial options
_cgi.args   = --cgi +quit --exit=BEGIN0
test.cgibad%:       EXE.pl      = ../$(SRC.cgi)

# some characters are enclosed in _ and _ for better readability
test.cgibad--opt_%: _cgi.args  += --opt=ok.to.show.failed-status
test.cgibad--cmd_%: _cgi.args  += --cmd=list
test.cgibad--env_%: _cgi.args  += --env=not-allowed
test.cgibad--exe_%: _cgi.args  += --exe=not-allowed
test.cgibad--lib_%: _cgi.args  += --lib=not-allowed
test.cgibad--cal_%: _cgi.args  += --call=not-allowed
test.cgibad--ssl_%: _cgi.args  += --openssl=not-allowed
test.cgibad--c01_%: _cgi.args  += '--bad-char=_<_'
test.cgibad--c02_%: _cgi.args  += '--bad-char=_>_'
test.cgibad--c03_%: _cgi.args  += '--bad-char=_;_'
test.cgibad--c04_%: _cgi.args  += '--bad-char=_~_'
test.cgibad--c05_%: _cgi.args  += '--bad-char=_?_'
#test.cgibad--c06_%: _cgi.args  += '--bad-char=_\$$_'
test.cgibad--c07_%: _cgi.args  += '--bad-char=_%_'
test.cgibad--c08_%: _cgi.args  += '--bad-char=_\"_'
test.cgibad--c09_%: _cgi.args  += '--bad-char=_\`_'
test.cgibad--c10_%: _cgi.args  += '--bad-char=_*_'
test.cgibad--c11_%: _cgi.args  += '--bad-char=_(_'
test.cgibad--c12_%: _cgi.args  += '--bad-char=_)_'
test.cgibad--c13_%: _cgi.args  += '--bad-char=_[_'
test.cgibad--c14_%: _cgi.args  += '--bad-char=_]_'
test.cgibad--c15_%: _cgi.args  += '--bad-char=_{_'
test.cgibad--c16_%: _cgi.args  += '--bad-char=_}_'
test.cgibad--c17_%: _cgi.args  += '--bad-char=_^_'
test.cgibad--c18_%: _cgi.args  += '--bad-char=_|_'
test.cgibad--c20_%: _cgi.args  += '--bad-char=_\#_'

test.cgibad%:
	@$(TARGET_VERBOSE)
	@$(eval _host := $(shell echo "$*" | awk -F_ '{print $$NF}'))
	@cd  $(TEST.dir) ; \
	$(MAKE) -i no.message-exit.BEGIN0 EXE.pl=$(EXE.pl) \
		TEST.init="" \
		TEST.args="$(_cgi.args) --host=$(_host)"

ALL.testcgiopt  = $(shell awk -F% '/^test.cgibad--/ {print $$1}' $(_MYSELF.cgi))
ALL.test.cgiopt = $(ALL.testcgiopt:%=%any.FQDN)
ALL.test.cgi    = $(ALL.test.cgiopt) $(ALL.cgi.badhosts) $(ALL.cgi.badIPs)

test.cgi.badhosts: $(ALL.cgi.badhosts)
test.cgi.badIPs:   $(ALL.cgi.badIPs)
test.cgi.badall:   test.cgi.badhosts test.cgi.badIPs
test.cgi.badopt:   $(ALL.test.cgiopt)

test.cgi:          $(ALL.test.cgi)

_TEST.CGI.log   = $(TEST.logdir)/test.cgi.log-$(_TODAY_)
# use 'make -i ...' because we have targets which fail, which is intended
$(_TEST.CGI.log):
	@echo "# Makefile.cgi 1.11: make test.cgi.log" > $@
	@$(MAKE) -i test.cgi >> $@ 2>&1

test.cgi.log: $(_TEST.CGI.log)
	@$(TARGET_VERBOSE)
	@diff $(TEST.logdir)/$@ $(_TEST.CGI.log) \
	    && rm $(_TEST.CGI.log) \
	    || mv $(_TEST.CGI.log) $(TEST.logdir)/$@
	@-test -f $(TEST.logdir)/$@  ||  mv $(_TEST.CGI.log) $(TEST.logdir)/$@
	@ls -l  $(TEST.logdir)/$@*
# TODO: same target as test.warnings.log

.PHONY: test.cgi.log

#_____________________________________________________________________________ 
#_____________________________________________________________________ test __|

# feed main Makefile
ALL.tests      += $(ALL.test.cgi)
ALL.tests.log  += test.cgi.log
