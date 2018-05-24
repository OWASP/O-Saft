#! /usr/bin/make -rRf
#?
#? NAME
#?      Makefile        - makefile for testing O-Saft
#?
#? SYNOPSYS
#?      make [options] [target] [...]
#?
#? DESCRIPTION
#?      Traditional Makefile to perform testing tasks for O-Saft project.
#?
#? LIMITATIONS
#?       Requires GNU Make > 2.0.
#?
# HACKER's INFO
#       For details please see ../Makefile .
#
#? VERSION
#?      @(#) Makefile 1.3 18/05/25 01:14:59
#?
#? AUTHOR
#?      18-apr-18 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

MAKEFLAGS      += --no-builtin-variables --no-builtin-rules
.SUFFIXES:

first-target-here--is-default: testhelp

_SID.test       = 1.3
# define our own SID as variable, if needed ...

ifndef ALL.Makefiles                                                           
include Makefile.inc
# defines macros if called directly (not from ../makefile)
endif

#_____________________________________________________________________________
#________________________________________________________________ variables __|

# source test file
TEST.dir        = test
TEST.do         = SSLinfo.pl \
		  o-saft_bench \
		  critic_345.sh \
		  test-bunt.pl.txt \
		  test-o-saft.cgi.sh
TEST.rc         = .perlcriticrc
SRC.test        = \
		  $(TEST.do:%=$(TEST.dir)/%) \
		  $(TEST.rc:%=$(TEST.dir)/%)
ALL.test        = $(SRC.test)

# internal used tools (paths hardcoded!)
EXE.bench       = test/o-saft_bench
EXE.test.bunt   = test/test-bunt.pl.txt
EXE.test.cgi    = test/test-o-saft.cgi.sh

_TODAY_         = $(shell date +%Y""%m%d)

#_____________________________________________________________________________
#___________________________________________________________ default target __|

testhelp:
	@echo " $(_HELP_LINE_)$(_NL) $(_HELP_INFO_)$(_NL) $(_HELP_LINE_)$(_NL)"
	@echo $(MORE-test)     ; # no quotes!
	@echo $(MORE-warnings)
	@echo $(MORE-misc)

.PHONY: testhelp

#_____________________________________________________________________________
#_____________________________________________________ internal test target __|

# internal information (nothing related to $(Project))
# Note that the information is from the main Makefile, probably ../Makefile
test-file-1:
test-file-2:
test-file-3:
test-target: test-file-1 test-file-2 test-file-3
	@echo 'test-target: test-file-1 test-file-2 test-file-3'
	@echo '# taget to show some make valiables:'
	@echo '# $$@  = $@ #'
	@echo '# $$<  = $< #'
	@echo '# $$?  = $? #'
	@echo '# $$^  = $^ #'
	@echo '# $$+  = $+ #'
	@echo '# $$|  = $| #'
	@echo '# $$%  = $% #'
	@echo '# $$*  = $* #'
	@echo '# $$>  = $> #'
	@echo '# $$-  = $- #'
	@echo '# $$(MAKE)          = $(MAKE)'
	@echo '# $$(MAKELEVEL)     = $(MAKELEVEL)'
	@echo '# $$(MAKEFILE)      = $(MAKEFILE)'
	@echo '# $$(MAKEFILES)     = $(MAKEFILES)'
	@echo '# $$(MFLAGS)        = $(MFLAGS)'
	@echo '# $$(MAKEFLAGS)     = $(MAKEFLAGS)'
	@echo '# $$(MAKEOVERRIDES) = $(MAKEOVERRIDES)'
	@echo '# $$(.VARIABLES)    = $(.VARIABLES)'

#_____________________________________________________________________________
#______________________________________________________ targets for testing __|

HELP-_test      = ______________________________________ targets for testing _
HELP-testhelp   = print more targets for testing
HELP-tests      = make all tests
HELP-test       = alias for tests

#_____________________________________________________________________________
#_________________________________________________________ testing warnings __|

MORE-warnings    = " \
\#               __________________________________________ test warnings _$(_NL)\
 message-STR     - test for specific STR in output of '$(SRC.pl)'$(_NL)\
 warning-NR      - test for specific messages number NR of '$(SRC.pl)'$(_NL)\
 test-warnings   - test **WARNING messages of '$(SRC.pl)'$(_NL)\
 test-warnings.log    - test **WARNING messages of '$(SRC.pl)' and compare with previous one$(_NL)\
 gen-warning-template - generate template Makefile for testing warning messages$(_NL)\
 show-warnings-todo   - show not implemented tests for warnings$(_NL)\
 show-warnings-difficult - show tests for warnings which are difficult to implement$(_NL)\
"

# testing warning messages
_TMP.rc         = /tmp/o-saft.tmprc
#
# Each warning-* target defines its (conditional) command to be used with
# $(SRC.pl). If the definition starts with the literal string "TODO:" the
# target will only print the text (see message-%).
# The TODO texts ending with  "difficult ..." mark messages, which cannot
# tested easily.
warning-002: TEST.args  = TODO: testing openssl returning error, difficult ...
warning-003: TEST.args  = TODO: testing openssl failed with allocate memory, difficult ...
warning-004: TEST.args  = TODO: testing perl returned status, difficult ...
warning-005: TEST.args  = TODO: testing missing IO/Socket/SSL.pm
warning-006: TEST.args  = TODO: testing missing IO/Socket/INET.pm
warning-007: TEST.args  = TODO: testing missing Net/DNS.pm
warning-008: TEST.args  = TODO: testing missing Time/Local.pm
#warning-009: TEST.args  = free
warning-010: TEST.args  = TODO: testing die, missing Net/SSLhello.pm
warning-011: TEST.args  = TODO: testing die, missing Net/SSLinfo.pm
warning-012: TEST.args  = TODO: testing die, missing Net::SSLeay.pm
warning-013: TEST.args  = TODO: testing die, missing o-saft-man.pm
warning-014: TEST.args  = TODO: testing die, missing Net::SSLeay.pm
warning-015: TEST.args  = TODO: testing die, no ciphers found, may happen with openssl pre 1.0.0, difficult ...
warning-020: TEST.args  = TODO: testing die, CGI mode requires strict settings
#warning-040: TEST.args  = free
warning-041: TEST.args  = s_client                          +quit
warning-042: TEST.args  = +cn --port=' ' unknown-host       +quit
warning-043: TEST.args  = --rc=$(_TMP.rc) --v               +quit
warning-043:                                     TEST.rc = --cfg_cmd=new_command=quit
warning-044: TEST.args  = +zlib +lzo +open_pgp +fallback     +quit
#warning-045: TEST.args  = free
#warning-046: TEST.args  = free
warning-047: TEST.args  = +info  +cn                        any-host
warning-048: TEST.args  = +check +cn                        any-host
warning-049: TEST.args  = +unknown_command                  +quit
warning-050: TEST.args  = +cn --port=                       +quit
#warning-051: TEST.args  = free
warning-052: TEST.args  = --rc=$(_TMP.rc)
warning-052:                                     TEST.rc = "--option=-with_trailing_spaces   "
warning-053: TEST.args  = --capath='/path with spaces'      +quit
warning-054: TEST.args  = --legacy=unknown_legacy           +quit
warning-055: TEST.args  = --format=unknown_format           +quit
warning-056: TEST.args  = --range=unknown_range             +quit
warning-057: TEST.args  = --ciphercurves=unknown            +quit
warning-063: TEST.args  = --cipher=unknown +cipher          any-host
warning-064: TEST.args  = +sts --no-http                    any-host
#warning-065: TEST.args  = free
warning-066: TEST.args  = --ignore-out=cn +cn               any-host
warning-067: TEST.args  = --ignore-out=cn +cn --v           any-host
warning-068: TEST.args  = --ignore-out=cn +cn --v           any-host
warning-069: TEST.args  = --sniname=wrong +cn               $(TEST.host)
warning-070: TEST.args  = --cfg_cmd=$(_TMP.rc)              +quit
warning-070: TEST.args  = TODO: need special test target which uses unredable --cfg_cmd=$(_TMP.rc)
warning-071: TEST.args  = --cfg_unknown=dummy=dummy         +quit
warning-072: TEST.args  = --cfg_cmd=$(_TMP.rc) --cgi        +quit
warning-073: TEST.args  = --cfg_cmd=invalid_default_command=default +quit
#?# warning-074: TEST.args  = --rc=$(_TMP.rc)                +quit
#?# warning-074:                                     TEST.rc = "--cfg_cmd=dummy=cn unknown_command"
warning-074: TEST.args  = --cfg_cmd=dummy=unknown_command   +quit
#warning-075: TEST.args  = free
warning-076: TEST.args  = --cfg_score=dummy=invalid_value   +quit
warning-080: TEST.args  = TODO: testing Net::SSLeay < 1.49
warning-111: TEST.args  = --mx --nodns                      +quit
warning-111: TEST.args  = TODO: testing missing Net/DNS.pm
warning-112: TEST.args  = +sts_expired                      +quit
warning-112: TEST.args  = TODO: testing missing Time/Local.pm need by +sts_expired
warning-120: TEST.args  = TODO: testing ancient perl
warning-121: TEST.args  = TODO: testing ancient module
warning-122: TEST.args  = TODO: testing ancient Net::SSLeay
warning-123: TEST.args  = TODO: testing ancient IO::Socket
warning-124: TEST.args  = TODO: testing ancient IO::Socket::SSL
warning-125: TEST.args  = TODO: testing openssl < 1.0.0
warning-126: TEST.args  = TODO: testing missing ALPN functionality
warning-127: TEST.args  = TODO: testing Net::SSLeay < 1.56, ALPN disabled
warning-128: TEST.args  = TODO: testing openssl < 1.0.2, ALPN disabled
warning-129: TEST.args  = TODO: testing missing NPN functionality
warning-130: TEST.args  = TODO: testing Net::SSLeay < 1.46, ALPN disabled
#warning-131: TEST.args  = free
warning-132: TEST.args  = TODO: testing openssl < 1.0.1, ALPN disabled
warning-133: TEST.args  = TODO: testing Net::SSLeay without OCSP
warning-134: TEST.args  = TODO: testing Net::SSLeay without EC
warning-135: TEST.args  = TODO: testing Net::SSLeay < 1.49
warning-140: TEST.args  = +cipherraw --dtlsv1               +quit
warning-141: TEST.args  = +cipherraw --dtlsv9               +quit
warning-141: TEST.args  = TODO: testing wrong or unsupported SSL protocol
#warning-142: TEST.args  = free
warning-143: TEST.args  = TODO: testing SSL protocol not supported by Net::SSLeay, difficult ...
warning-144: TEST.args  = TODO: testing missing openssl s_client support for -alpn or -npn, difficult ...
warning-145: TEST.args  = TODO: testing missing openssl s_client support for -alpn or -npn, difficult ...
warning-146: TEST.args  = TODO: testing missing openssl -tlsextdebug option
warning-147: TEST.args  = TODO: testing missing openssl executable in Net::SSLinfo
warning-148: TEST.args  = TODO: testing missing openssl version -d failed, difficult ...
warning-149: TEST.args  = --openssl=/does/not/exist         +quit
warning-201: TEST.args  = +cn                               unknown-host
warning-202: TEST.args  = +cn --exit=HOST1                  www.skype.com
#                       # scary: need a reliable FQDN here -^^^^^^^^^^^^^
#warning-203: TEST.args  = free
warning-204: TEST.args  = TODO: testing connection without SNI, difficult ...
warning-205: TEST.args  = TODO: testing connection failed, difficult ...
warning-206: TEST.args  = TODO: testing connection witout SNI errors from Net::SSLinfo, difficult ...
warning-207: TEST.args  = TODO: testing connection with openssl failed, difficult ...
warning-208: TEST.args  = TODO: testing +check without openssl on Windows, difficult ...
warning-209: TEST.args  = TODO: testing missing SSL version, difficult ...
warning-301: TEST.args  = TODO: testing continous connection errors, difficult ...
warning-302: TEST.args  = TODO: testing max connection errors, difficult ...
warning-303: TEST.args  = TODO: testing unsupported Net::SSLeay::CTX_v2_new, difficult ...
warning-304: TEST.args  = TODO: testing unsupported Net::SSLeay::CTX_v3_new, difficult ...
warning-305: TEST.args  = TODO: testing connection _usesocket failed, difficult ...
warning-311: TEST.args  = TODO: testing  empty  result from openssl, difficult ...
warning-312: TEST.args  = TODO: testing strange result from openssl, difficult ...
warning-312: TEST.args  = TODO: testing unknown result from openssl, difficult ...
warning-321: TEST.args  = TODO: testing _isbleed failed to connect, difficult ...
warning-322: TEST.args  = TODO: testing _isbleed with openTcpSSLconnection failed, difficult ...
warning-323: TEST.args  = TODO: testing heartbleed: no reply, difficult ...
warning-324: TEST.args  = TODO: --sniname=wrong +cn
#                       # scary: need a reliable FQDN here -^^^^^^^^^^^^^ www.skype.com
warning-325: TEST.args  = TODO: testing connection failed, HTTP disabled, difficult ...
warning-331: TEST.args  = TODO: testing _isccs: failed to connect, difficult ...
warning-332: TEST.args  = TODO: testing _isccs: no reply, difficult ...
warning-409: TEST.args  = --sslv2 --sni +cipherall --exit=HOST4 $(TEST.host)
warning-410: TEST.args  = --sslv2 --sni +cipher    --exit=HOST4 $(TEST.host)
warning-411: TEST.args  = TODO: testing checked cipher does not match returned cipher, difficult ...
warning-601: TEST.args  = TODO: testing connection failed with protocol error, difficult ...
warning-602: TEST.args  = TODO: testing connection type name mismatch, difficult ...
warning-631: TEST.args  = TODO: testing SSL protocol mismatch for cipher, difficult ...
warning-801: TEST.args  = TODO: testing connection returning unknown label, difficult ...
warning-811: TEST.args  = TODO: ancient openssl version: using '-msg' option to get DH parameters
warning-821: TEST.args  = TODO: can not print certificate sizes without a certificate, --no-cert
warning-831: TEST.args  = --testing-+quit__without__--trace=arg +quit
warning-841: TEST.args  = TODO: used openssl version differs from compiled Net:SSLeay
warning-851: TEST.args  = TODO: ancient version Net::SSLeay < 1.49
warning-861: TEST.args  = TODO: not all ciphers listed

# generate list of all targets dynamically from our definitions above
ALL.warnings    = $(shell awk '/^warning-...:/{sub(":","");print $$1}' $(ALL.Makefiles) | sort -u)

_TEST.template  = test/test-warning.Makefile-template
$(_TEST.template): $(SRC.pl)
	@echo "# generated template targets to test **WARNING messages" > $@
	@echo "# targets use the message text as TODO (see Makefile)"  >> $@
	@echo "# Note: texts for TEST.args should not contain ; | ()"  >> $@
	@echo "# Note: not all texts my be useful, it's a template!"   >> $@
	@echo ""                                                       >> $@
	perl -nle 'm/^\s*_?warn/ && do {\
		s/^[^"]*"([^"]*).*/warning-$$1/;\
		s/:/: TEST.args  = TODO:/;\
		print}' $^ \
	| sort >> $@
	@-ls -l $@

gen-warning-template: $(ALL.Makefiles) $(_TEST.template)
# TODO: Makefile dependency does not work, probably need to use $(MAKE)

show-warnings-todo:
	grep "^warning..*TODO" $(TEST.dir)/Makefile

show-warnings-difficult:
	grep "^warning..*difficult" $(TEST.dir)/Makefile

# Testing for messages (i.e **WARNING) works as follows:
#   call $(EXE.pl) with command and/or options in question
#   then search (grep) output for message (number in case of warnings)
# For some behaviours of $(EXE.pl) a RC-file is required.
# For testing all different warning-* targets, the pattern rule  message-% is
# used, which gets the message number from the automatic variable $*  and the
# arguments for $(SRC.pl) with following Makefile variables:
#   $(TEST.args)    - command, options and hostname to be passed to $(EXE.pl)
#                     +quit  command or  other command and hostname is needed
#                     for testing the warning message
#   $(TEST.rc)      - content of RC-file to be used by $(EXE.pl)
# These variables are set conditinally for each target (see above).
# Some tests are not yet implemented, or difficult to implement. In this case
# $(TEST.args) contains a string starting with "TODO:". The  message-%  target
# tests the variable for this string and then simply prints it. Otherwise the
# check will be performed (see  if - else -fi  in target).
# Note:  even '$(_TMP.rc)'  is generated for each call,  it will only be used
# when requested with the  --rc=$(_TMP.rc)  option.
# Hint: we can even test for any string in output, example
#   make message-Certificate TEST.args="+cn localhost"
message-%: $(SRC.pl)
	@$(TARGET_VERBOSE)
	-if expr "$(TEST.args)" ":" "^TODO" >/dev/null ; then \
	    echo "$@:    $(TEST.args)"; \
	else \
	    echo "$(TEST.rc)" > $(_TMP.rc) ; \
	    $(EXE.pl) $(TEST.args) | grep $* ; \
	    rm -f $(_TMP.rc) ; \
	fi

warning-%: message-%
	@echo -n ""

test-warnings: $(ALL.warnings)

# $(_WARNING.log) calls "make -s" to avoid printing of executed commands
_WARNING.log    = $(TEST.dir)/test-warnings-$(_TODAY_).log
$(_WARNING.log):
	@$(MAKE) -s $(ALL.warnings) > $@

# Target should create a new logfile, then compare it with the curennt one.
# If current logfile is missing use newly created one: "mv ... || cp ..." .
# this avoid errors when the file is missing.
# If the diff returns nothing, mv newlycreated logfile to target, otherwise
# restore previous one.
test-warnings.log: $(_WARNING.log) $(SRC.pl)
	-mv $(TEST.dir)/$@     $@-last \
	 || cp $(_WARNING.log) $@-last
	diff   $@-last $(_WARNING.log) \
	 && mv $(_WARNING.log) $(TEST.dir)/$@ && rm $@-last \
	 || mv $@-last         $(TEST.dir)/$@
	@ls -l  $(TEST.dir)/$@

.PHONY: test-warnings.log

#_____________________________________________________________________________
#______________________________________________________ testing +cmd --opt  __|

MORE-test       = " \
\#               ________________________________________ summary targets _$(_NL)\
 test.help       - test  help   commands and options$(_NL)\
 test.info       - test  info   commands with localhost$(_NL)\
 test.check      - test  check  commands with localhost$(_NL)\
 test.cipher     - test  cipher commands with localhost$(_NL)\
 test.summary    - test summary commands with localhost$(_NL)\
 test.local      - test commands with localhost$(_NL)\
 testrun-CMD     - test specific test target CMD$(_NL)\
 testrun-CMD.log - test specific test target CMD and store in test/CMD.log$(_NL)\
"

test_+help-+VERSION:        TEST.args   = +VERSION
test_+help-+help:           TEST.args   = +help=command
test_+help-+ciphers:        TEST.args   = +ciphers -V
test_+help-+version:        TEST.args   = +version
test_+help-+version--v:     TEST.args   = +version --v --usr
test_+help---v+vers:        TEST.args   = --v +version
test_+help---v+help:        TEST.args   = --v +help
test_-help-command:         TEST.args   = --help=command
test_-help-options:         TEST.args   = --help=options
test_-help-cmd:             TEST.args   = --help=cmd
test_-help-opt:             TEST.args   = --help=opt
test_-help-alias:           TEST.args   = --help=alias
test_-help-glossar:         TEST.args   = --help=glossar
test_-help-rfc:             TEST.args   = --help=rfc
test_-help-links:           TEST.args   = --help=links
test_-help-check:           TEST.args   = --help=check
test_-help-regex:           TEST.args   = --help=regex
test_-help-WHY:             TEST.args   = --help=WHY
test_-help-CHECK:           TEST.args   = --help=CHECK
test_-help-cfg-text:        TEST.args   = --help=cfg-text
test_-help-gen-wiki:        TEST.args   = --help=gen-wiki
test_-help-gen-html:        TEST.args   = --help=gen-html
test_-help-gen-cgi:         TEST.args   = --help=gen-cgi
test_-help--yeast-data:     TEST.args   = --yeast-data
test_-help--yeast-prot:     TEST.args   = --yeast-prot
test_+info:                 TEST.args   = +info
test_+info--trace-cmd:      TEST.args   = +info   --trace-cmd
test_+info--trace-key:      TEST.args   = +info   --trace-key
test_+info--trace-key-norc: TEST.args   = +info   --trace-key --norc
test_+check:                TEST.args   = +check
test_+check--trace-key:     TEST.args   = +check  --trace-key
test_+check--trace-key-norc:  TEST.args   = +check  --trace-key --norc
test_+check--trace-norc:    TEST.args   = +check  --trace-cmd --trace-time --trace=2 --norc
test_+check--nossltls:      TEST.args   = +check  --nosslv2 --nosslv3 --notlsv1 --notlsv11 --notlsv12 --notlsv13
test_+cipher:               TEST.args   = +cipher
test_+cipher--force-openssl:  TEST.args   = +cipher --force-openssl
test_+cipher--cipher-openssl: TEST.args   = +cipher --cipher-openssl
test_+cipherall:            TEST.args   = +cipherall
test_+cipherraw:            TEST.args   = +cipherraw
test_+cipher-dh:            TEST.args   = +cipher-dh
test_+cipher-default:       TEST.args   = +cipher-default
test_+ciphercheck:          TEST.args   = +ciphercheck
test_+cipher--nossltls:     TEST.args   = +cipher --nosslv2 --nosslv3 --notlsv1 --notlsv11 --notlsv12 --notlsv13
test__vuln-+BEAST:          TEST.args   = +BEAST
test__vuln-+CRIME:          TEST.args   = +CRIME
test__vuln-+DROWN:          TEST.args   = +DROWN
test__vuln-+FREAK:          TEST.args   = +FREAK
test__vuln-+POODLE:         TEST.args   = +POODLE
test__vuln-+logjam:         TEST.args   = +logjam
test__vuln-+lucky13:        TEST.args   = +lucky13
test__vuln-+Sloth:          TEST.args   = +Sloth
test__vuln-+Sweet32:        TEST.args   = +Sweet32
test__summ-+bsi:            TEST.args   = +bsi
test__summ-+TR-02102+:      TEST.args   = +TR-02102+
test__summ-+EV:             TEST.args   = +EV
test__summ-+quick:          TEST.args   = +quick --trace-arg
test__summ-+http:           TEST.args   = +http
test__summ-+hsts:           TEST.args   = +hsts
test__summ-+ocsp:           TEST.args   = +ocsp
test__summ-+preload:        TEST.args   = +preload
test__summ-+protocols:      TEST.args   = +protocols
test__summ-+fingerprints:   TEST.args   = +fingerprints
test__summ-+sizes:          TEST.args   = +sizes
test__summ-+pfs:            TEST.args   = +pfs
test__summ-+sts:            TEST.args   = +sts
test__summ-+sni:            TEST.args   = +sni
test__summ-+vulns:          TEST.args   = +vulns

# generate list of all targets dynamically from our definitions above
# note that . inside // below is a meta character
# note: no sort because we want the sequence as defined above
ALL.testhelp    = $(shell awk '/^test_.help-/  {sub(":","");print $$1}' $(ALL.Makefiles))
ALL.testinfo    = $(shell awk '/^test_.info-/  {sub(":","");print $$1}' $(ALL.Makefiles))
ALL.testcheck   = $(shell awk '/^test_.check-/ {sub(":","");print $$1}' $(ALL.Makefiles))
ALL.testcipher  = $(shell awk '/^test_.cipher/ {sub(":","");print $$1}' $(ALL.Makefiles))
ALL.testsummary = $(shell awk '/^test_.summ-/  {sub(":","");print $$1}' $(ALL.Makefiles))
ALL.testlocal   = $(shell awk '/^test_.local-/ {sub(":","");print $$1}' $(ALL.Makefiles))

ALL.tests       = \
		  $(ALL.testhelp) \
		  $(ALL.testinfo) \
		  $(ALL.testcheck) \
		  $(ALL.testcipher) \
		  $(ALL.testsummary) \
		  $(ALL.testlocal)
ALL.tests.log   = $(ALL.tests:%=%.log)

testrun-%__nur-verwenden-wenn-mehrer-targets-in-ein-File: $(SRC.pl)
	@$(TARGET_VERBOSE)
	@echo "{## `date +%T`: $(EXE.pl) $(TEST.args) ..."
	@cd  $(TEST.dir)  &&   $(EXE.pl) $(TEST.args) $(TEST.host)
	@echo "##}"

testrun-%: $(SRC.pl)
	@$(TARGET_VERBOSE)
	@cd  $(TEST.dir)  &&   $(EXE.pl) $(TEST.args) $(TEST.host)

test_%: testrun-%
	@echo -n ""

test_%.log:
	@$(TARGET_VERBOSE)
	@$(MAKE) -s test_$* > $@ 2>&1
	@-diff $(TEST.dir)/$@ $@ \
	    && rm $@ \
	    || mv $@ $(TEST.dir)/test_$*-$(_TODAY_).log
	@ls -l  $(TEST.dir)/$@*

test.help:      $(ALL.testhelp)
test.info:      $(ALL.testinfo)
test.check:     $(ALL.testcheck)
test.cipher:    $(ALL.testcipher)
test.summary:   $(ALL.testsummary)
test.local:     $(ALL.testlocal)
tests:          $(ALL.tests)

# $(_TEST.log) calls "make -s" to avoid printing of executed commands
_TEST.log       = $(TEST.dir)/test-test-$(_TODAY_).log
$(_TEST.log):
	@echo _TEST.log
	@$(MAKE) -s $(ALL.tests.log) > $@

test-tests.log: $(SRC.pl) $(ALL.tests.log)
	@echo -n ""

#_____________________________________________________________________________
#____________________________________________________________ various tests __|

MORE-misc        = " \
\#               ____________________________________________ misc. tests _$(_NL)\
 bench           - call '$(EXE.bench)' for some benchmarks$(_NL)\
 bench.log       - call '$(EXE.bench)' and save result in '$(BENCH.times)'$(_NL)\
 test.bunt       - test '$(CONTRIB.dir)/bunt.pl' with sample file$(_NL)\
 test.cgi        - test invalid IPs to be rejected by '$(SRC.cgi)'$(_NL)\
"

BENCH.times       = $(EXE.bench).times
BENCH.host        = $(TEST.host)
bench:
	$(EXE.bench) $(BENCH.host)
	@echo "# use '$(MAKE) bench.log' to save result in '$(BENCH.times)'"
bench.log:
	$(EXE.bench) $(BENCH.host) >> $(BENCH.times)

test.cgi: $(EXE.test.cgi) $(SRC.cgi)
	@$(TARGET_VERBOSE)
	$(EXE.test.cgi)

test.bunt: $(EXE.test.bunt)
	@$(TARGET_VERBOSE)
	-cat $(EXE.test.bunt) | $(CONTRIB.dir)/bunt.pl

.PHONY: bench bench.log test.bunt test.cgi

#_____________________________________________________________________________
#_________________________________________________ targets for code quality __|

HELP-_qa        = _________________________________ targets for code quality _
HELP-critichelp = print more details about  critic-*  targets
HELP-critic     = check files with perlcritic
HELP-critic345  = check files with perlcritic for severity 3,4,5 using test/critic_345.sh

MORE-critic     = " \
\# More  critic  targets exist, calling perlcritic with additional options$(_NL)\
$(_HELP_LINE_)$(_NL)\
$(_HELP_INFO_)$(_NL)\
$(_HELP_LINE_)$(_NL)\
\#               _______________________________________________ severity _$(_NL)\
 critic          - perlcritic --severity 5 <all files>$(_NL)\
 critic-5        - perlcritic --severity 5 <all files>$(_NL)\
 critic-4        - perlcritic --severity 4 <all files>$(_NL)\
 critic-3        - perlcritic --severity 3 <all files>$(_NL)\
 critic-2        - perlcritic --severity 2 <all files>$(_NL)\
\#               _____________________________________________ statistics _$(_NL)\
 critic-count    - perlcritic --severity 5 -count$(_NL)\
 critic-stat     - perlcritic --severity 5 --statistics-only $(_NL)\
 critic-stat-4   - perlcritic --severity 4 --statistics-only $(_NL)\
 critic-stat-3   - perlcritic --severity 3 --statistics-only $(_NL)\
\#               ___________________________________ single file severity _$(_NL)\
 c5-FILE         - perlcritic --severity 5 FILE$(_NL)\
 c4-FILE         - perlcritic --severity 4 FILE$(_NL)\
 c3-FILE         - perlcritic --severity 3 FILE$(_NL)\
\#               ___________________________ single file verbose severity _$(_NL)\
 c5v-FILE        - perlcritic --severity 5 FILE --verbose 10$(_NL)\
 c4v-FILE        - perlcritic --severity 4 FILE --verbose 10$(_NL)\
 c3v-FILE        - perlcritic --severity 3 FILE --verbose 10$(_NL)\
\#               _____________________ targets with pretty-printed output _$(_NL)\
 TARGETp         - call TARGET and pretty print output$(_NL)\
$(_HELP_LINE_)$(_NL)\
\# Where   FILE   is any of the *.pm or *.pl files (including path).$(_NL)\
\# Where  TARGET  is any of:$(_NL)\
\#        critic critic-5 critic-4 critic-3 critic-2 critic-count critic-stat$(_NL)\
\#$(_NL)\
\# None of the  critic-*  targets is available with the  -v or -vv  suffix$(_NL)\
\# because verbose does not make sense here.$(_NL)\
\#$(_NL)\
\# Note about perlcritic used here:$(_NL)\
\#   * perlcritic is executed in directory '$(CRITIC.dir)'$(_NL)\
\#   * perlcritic uses '$(CRITIC.dir)/$(CRITIC.rc)'$(_NL)\
\# See also '$(CONTRIB.dir)/critic.sh'$(_NL)\
"

.PHONY: critichelp critic critic-5 critic-4 critic-3 critic-2

critichelp:
	@echo $(MORE-critic)    ; # no quotes!
critic.help: critichelp
criticdoc:   critichelp

CRITIC.dir      = $(TEST.dir)
CRITIC.rc       = .perlcriticrc
CRITIC.severity = -5
CRITIC.opt      =

CRITIC.pretty   =

$(CRITIC.dir):
	@$(TARGET_VERBOSE)
	@mkdir -p $(CRITIC.dir)

# target prints command with echo so that it is also shown when called with
# "make -s critic ..."
critic: $(CRITIC.dir)
	@$(TARGET_VERBOSE)
	@echo   "perlcritic $(ALL.critic) $(CRITIC.severity) $(CRITIC.opt)"
	@-cd $(CRITIC.dir) && \
	  perlcritic $(ALL.critic:%=../%) $(CRITIC.severity) $(CRITIC.opt)

# same target as above but piped to filter for pretty printing
# the filter cannot be a pipe because we would loose the coloured output from
# perlcritic then
critic-pretty: $(CRITIC.dir)
	@$(TARGET_VERBOSE)
	@echo   "perlcritic $(ALL.critic) $(CRITIC.severity) $(CRITIC.opt)"
	@-cd $(CRITIC.dir) && \
	  perlcritic $(ALL.critic:%=../%) $(CRITIC.severity) $(CRITIC.opt) \
	  | awk '\
    { gsub(/\.$$/,"");  C=" remove trailing . (for --statistics-only)"; }\
    /OK$$/{ $$2=$$1; $$1="OK\t"; $$3=""; C=" toggle $1 and $2"; } \
    /: *[0-9][0-9]*$$/{ $$0=sprintf("%d\t%s",$$2,$$1); C=" toggle $1 and $2"; } \
    /^Average /{ x=$$NF; $$NF=""; $$0=sprintf("%9s %s",x,$$0); } \
    /^Violatio/{ x=$$NF; $$NF=""; $$0=sprintf("%9s %s",x,$$0); } \
    /^[0-9 ][0-9 ,]* /{ x=$$1; $$1=""; $$0=sprintf("%9s %s",x,$$0); } \
    {\
      gsub(/\.\../,""); C=" remove leading ../"; \
      gsub(/\:$$/,"");  C=" remove trailing : (for --count)";  \
      gsub(/ was *$$/,"");  C=" remove trailing string (for --statistics-only)"; \
      print; \
    }\
'

critic-5:       CRITIC.severity = -5
critic-5p:      CRITIC.severity = -5
critic-5p:                           CRITIC.pretty = -pretty
critic-4:       CRITIC.severity = -4
critic-4p:      CRITIC.severity = -4
critic-4p:                           CRITIC.pretty = -pretty
critic-3:       CRITIC.severity = -3
critic-3p:      CRITIC.severity = -3
critic-3p:                           CRITIC.pretty = -pretty
critic-2:       CRITIC.severity = -2
critic-2p:      CRITIC.severity = -2
critic-2p:                           CRITIC.pretty = -pretty
critic-count:                        CRITIC.opt    = -count
critic-countp:                       CRITIC.pretty = -pretty
critic-stat:                         CRITIC.opt    = --statistics-only
critic-statp:                        CRITIC.opt    = --statistics-only
critic-statp:                        CRITIC.pretty = -pretty
critic-stat-4:                       CRITIC.opt    = --statistics-only
critic-stat-4:  CRITIC.severity = -4
critic-stat-3:                       CRITIC.opt    = --statistics-only
critic-stat-3:  CRITIC.severity = -3
critic-%:
	@$(MAKE) -s critic$(CRITIC.pretty) CRITIC.severity=$(CRITIC.severity) CRITIC.opt=$(CRITIC.opt)

c5-%:
	@$(MAKE) -s ALL.critic=$* critic$(CRITIC.pretty) CRITIC.severity=-5
c4-%:
	@$(MAKE) -s ALL.critic=$* critic$(CRITIC.pretty) CRITIC.severity=-4
c3-%:
	@$(MAKE) -s ALL.critic=$* critic$(CRITIC.pretty) CRITIC.severity=-3

c5v-%:
	@$(MAKE) -s ALL.critic=$* critic$(CRITIC.pretty) CRITIC.severity=-5 CRITIC.opt="--verbose 10"
c4v-%:
	@$(MAKE) -s ALL.critic=$* critic$(CRITIC.pretty) CRITIC.severity=-4 CRITIC.opt="--verbose 10"
c3v-%:
	@$(MAKE) -s ALL.critic=$* critic$(CRITIC.pretty) CRITIC.severity=-3 CRITIC.opt="--verbose 10"
# following targets required because they are not catched by critic-%; reason yet unknown
critic-5:       critic
critic-4:       critic
critic-3:       critic
critic-2:       critic
criticp:        critic-pretty

# TODO: replace functionality of test/critic_345.sh with targets above,
#       just redirect to logfiles is missing
critic345:
	-cd $(CRITIC.dir) && \
	  critic_345.sh $(ALL.critic)

#_____________________________________________________________________________
#__________________________________________________ targets for development __|

HELP-_dev       = __________________________________ targets for development _
HELP-tags       = generate tags file for vi(m)

$(GEN.tags): $(SRC.pl) $(ALL.pm) $(CHK.pl) $(SRC.cgi) $(SRC.tcl) $(ALL.Makefiles)
	ctags $^

