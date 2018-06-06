#! /usr/bin/make -rRf
#?
#? NAME
#?      Makefile        - makefile for testing O-Saft
#?
#? SYNOPSYS
#?      make [options] [target] [...]
#?
#? DESCRIPTION
#?      Traditional Makefile to perform testing tasks for o-saft,cgi
#?
#? LIMITATIONS
#?      Requires GNU Make > 2.0.
#?
# HACKER's INFO
#       For details please see ../Makefile .
#
#       Naming conventions for targets see Makefile.help.
#
#       TODO:
#          * complete with tests from test/test-o-saft.cgi.sh
#
#? VERSION
#?      @(#) Makefile.cgi 1.1 18/06/07 00:53:33
#?
#? AUTHOR
#?      18-apr-18 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

_SID.cgi    = 1.1

MAKEFLAGS  += --no-builtin-variables --no-builtin-rules
.SUFFIXES:

first-cgi-target-is-default: help.test.cgi

ifndef ALL.Makefiles
-include      Makefile.inc                                    
-include test/Makefile.inc
    # defines macros if called directly (not from ../Makefile)
endif

# FIXME: testing for includes not yet ready
ifeq (,$(_SID.test))
include testM
  ifeq (test,$(findstring test,$(PWD)))
  -include      Makefile
  -include   ../Makefile.help
  else
  -include test/Makefile
  -include      Makefile.help
  endif
endif

ifeq (test,$(findstring test,$(PWD)))
TEST.dir = .
    # if called inside test directory itself, TEST.dir must be redifined
endif


#_____________________________________________________________________________
#___________________________________________________________ default target __|

help.test.cgi:
	@echo " $(_HELP_LINE_)$(_NL) $(_HELP_INFO_)$(_NL) $(_HELP_LINE_)$(_NL)"
	@echo $(MORE-cgi)      ; # no quotes!

.PHONY: help.test.cgi


#_____________________________________________________________________________
#________________________________________________________________ variables __|

test.cgi.bad.hosts  = \
	localhost 

# the IP of hostname becomes part of the target name, hence IPv6 are not
# possible verbatime because they contain : in the name; the : must be escaped
# TODO: incomplete list for IPv6
test.cgi.bad.IPv6   = \
	\:\:1         ffff\:\:1  7f00\:1          ffff\:7f00\:1 \


# range from - - - - - - - - - - - - - - - - - - to
test.cgi.bad.IPs    = \
	$(test.cgi.bad.IPv6) \
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


ALL.cgi.bad.hosts   = $(test.cgi.bad.hosts:%=test.badhost-%)
ALL.cgi.bad.IPs     = $(test.cgi.bad.IPs:%=test.badhost-%)


#_____________________________________________________________________________
#__________________________________________________ targets for testing cgi __|

MORE-cgi        = " \
\#               ________________________________________ summary targets _$(_NL)\
 test.cgi.badhosts   - test that some hostnames are ignored in $(EXE.pl) $(_NL)\
 test.cgi.badIPs     - test that some IPs are ignored in $(EXE.pl) $(_NL)\
 test.cgi.badall     - test all bad and good IPs and hostnames $(_NL)\
 test.badhost-IP     - check a single IP or hostname if allowed in $(EXP.pl) $(_NL)\
"

# testing for invalid hostnames and IPs uses following command (example):
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
# The last line is missing for invalid IPs or hostnames. The test succeeds, if
# it is missing.
# The target used for each individual IP is  no.message.  It is a pattern rule
# in the test/Makefile and uses the variables  EXE.pl and TEST.args  which are
# passed as arguments to the recusive MAKE call.

test.badhost-%:
	cd  $(TEST.dir) ; \
	pwd && \
	$(MAKE) no.message-exit.BEGIN0 EXE.pl=o-saft.cgi \
		TEST.args="--cgi +quit --exit=BEGIN0 --host=$*"

test.cgi.badhosts: MAKEFLAGS      += --no-print-directory
test.cgi.badIPs:   MAKEFLAGS      += --no-print-directory
test.cgi.badall:   MAKEFLAGS      += --no-print-directory

test.cgi.badhosts: $(ALL.cgi.bad.hosts)
test.cgi.badIPs:   $(ALL.cgi.bad.IPs)
test.cgi.badall:   test.cgi.badhosts test.cgi.badIPs


