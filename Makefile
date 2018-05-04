#! /usr/bin/make -rRf
#?
#? NAME
#?      Makefile        - makefile for O-Saft project
#?
#? SYNOPSYS
#?      make [options] [target] [...]
#?
#? DESCRIPTION
#?      Traditional Makefile to perform common tasks for O-Saft project.
#?      For help about the targets herein, please see:
#?
#?          make
#?          make help
#?
#? LIMITATIONS
#?       Requires GNU make.
#?       Requires GNU sed for generating (target) INSTALL.sh.
#?
# HACKER's INFO
#       This  Makefile  uses mainly  make's built-in variables (aka macros) and
#       targets. None of them are disabled explicitly. Therefore some behaviour
#       may depend on the local make configuration.
#
#        Note: macro is a synonym for variable in Makefiles.
#        Note: macro definitions in Makefiles must not be sequential!
#
#    Remember make's variables:
#           $@    - target (fiel)
#           $+    - all dependencies of the target
#           $^    - all dependencies of the target (without duplicates)
#           $<    - first dependency of the target
#           $?    - dependencies newer than the target
#           $|    - "orde-only" dependencies
#           $*    - matching files of the rule
#           $%    - target (archive) member name (rarely used)
#        Use of $$ avoids evaluating $.
#
#    Variable, macro names
#        General rules for variable names in this Makefile:
#           * variable names consist only of characters a-zA-Z0-9_.
#           * variable names start with upper case letters
#
#        Following name prefixes are used:
#           * SRC  - defines a source file
#           * GEN  - defines a genarted file
#           * EXE  - defines a tools to be used
#           * ALL  - defines summary variables
#           * TEST - something related to the test/ directory
#           * CONTRIB  - something related to the contrib/ directory
#           * _    - names of internal (helper) variables
#                    (they are not intended to be overwritten on command line)
#           * HELP - defines texts to be used in  help  and  doc  target
#
#        Following names are used, which potentially conflict with make itself:
#           * ECHO     - echo command
#           * MAKE     - make command
#           * MAKEFILE - Makefile (i.g. myself, but may be redifined)
#
#        In general no quotes are used around texts in variables. Though, it is
#        sometimes necessary to use quotes to  force correct evaluation of used
#        variables in the text (mainly in target actions).
#
# HACKER's HELP
#        For extracting information from this  Makefile,  for example variables
#        and their definitions, following special syntax is used:
#           * all texts for documentation (help) are stored in variables
#           * all these variables are named ith the prefix  HELP-
#           * anything following the prefix is the name of an existing target
#             example:   HELP-doc  contains the description of the target  doc
#           * variable names with prefix  HELP-_  are treated as header texts
#             example:   HELP-_help = ____ targets for help about Makefile _
#
#        Targets in this Makefile are grouped. Each group is headed by the help
#        texts for the targets. The first line of this group should be a header
#        text describing the group. Example:
#           HELP-_group     = _______________________________ some targets _
#           HELP-help       = print overview of all targets
#           HELP-doc        = same as help, but evaluates variables
#        These variables are used by the  help  and  doc  target. Each of these
#        lines is printed as follows (example above):
#                    _______________________________ some targets _
#           help     - print overview of all targets
#           doc      - same as help, but evaluates variables
#
#        To extract and format the texts,  the targets use some external tools,
#        mainly, awk, sed and tr.  Each tool with its command line arguments is
#        defined as variable, see corresponding  EXE.*  variables.
#
#        The main difference between the target  help  and  doc  is, that  help
#        uses external tools to extract the information from the Makefile while
#        doc  uses make's functionality to display  the same information, which
#        then also evaluates variables used in the texts. Both targets must use
#        the same text (hence variable definitions).
#        The  EXE.*  macros used by these targets take care for the formatting.
#        They rely on the above conventions for variable names.
#
#        All variables used for help texts do not contain . (dot), but - (dash)
#        in their name. This simplifies matching the names, because the dash is
#        is not a meta character in RegEx and so must not be escaped.
#
#        Unfortunately, some of the macros use variables of the  Makefile, like
#        $(_TAB), while other macros must use the TAB character verbatim, which
#        is difficult to identify by human eyes.
#
#        Additional to the help targets described above, there're targets which
#        show information about variables and targets:
#            list, echo, show, macro, pmacro, target
#        These targets show the information, which is passed in a variable with
#        the same name as the target itself. Example:
#            make macro macro=MAKEFILE
#        To simplify this command line, a special pattern rule exists  for each
#        of these targets. Example:
#            make m-MAKEFILE
#
#? VERSION
#?      @(#) Makefile 1.10 18/05/05 00:27:43
#?
#? AUTHOR
#?      21-dec-12 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

MAKEFLAGS      += --no-builtin-variables --no-builtin-rules
.SUFFIXES:

first-target-is-default: default

MAKEFILE        = Makefile
# define variable for myself, it allows to use some targets with an other files
# Note  that  $(MAKEFILE)  is used where any Makefile is possible and  Makefile
#       is used when exactly this file is meant.

#_____________________________________________________________________________
#________________________________________________________________ variables __|

Project         = o-saft
ProjectName     = O-Saft
INSTALL.dir     = /usr/local/$(Project)
TEST.host       = localhost

# source files
SRC.lic         = yeast.lic
DEV.pl          = yeast.pl
CHK.pl          = checkAllCiphers.pl
OSD.dir         = OSaft/Doc
OSD.pm          = OSaft/Doc/Data.pm
OSD.txt         = \
		  coding.txt \
		  glossary.txt \
		  help.txt \
		  links.txt \
		  misc.txt \
		  rfc.txt \
		  tools.txt
SRC.txt         = $(OSD.txt:%=$(OSD.dir)/%)
NET.pm          = SSLinfo.pm \
		  SSLhello.pm
_CIPHER         = \
		  _ciphers_osaft.pm \
		  _ciphers_iana.pm \
		  _ciphers_openssl_all.pm \
		  _ciphers_openssl_low.pm \
		  _ciphers_openssl_medium.pm \
		  _ciphers_openssl_high.pm
OSAFT.pm        = Ciphers.pm error_handler.pm
USR.pm          = \
		  $(Project)-dbx.pm \
		  $(Project)-man.pm \
		  $(Project)-usr.pm \
		  osaft.pm
SRC.pm          = \
		  $(NET.pm:%=Net/%)   \
		  $(_CIPHER:%=OSaft/%) \
		  $(OSAFT.pm:%=OSaft/%) \
		  $(USR.pm) \
		  $(OSD.pm)
SRC.sh          = $(Project)
SRC.pl          = $(Project).pl
SRC.tcl         = $(Project).tcl $(Project)-img.tcl
SRC.cgi         = $(Project).cgi
SRC.docker      = \
		  $(Project)-docker \
		  $(Project)-docker-dev \
		  Dockerfile
SRC.rc          = .$(SRC.pl)

# test file
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

# contrib files
CONTRIB.dir     = contrib
CONTRIB.examples= filter_examples usage_examples
CONTRIB.post.awk= \
		  Cert-beautify.awk Cert-beautify.pl \
		  HTML-simple.awk HTML-table.awk \
		  JSON-array.awk JSON-struct.awk \
		  XML-attribute.awk XML-value.awk \
		  lazy_checks.awk
CONTRIB.post    = bunt.pl bunt.sh
CONTRIB.misc    = \
		  cipher_check.sh \
		  critic.sh \
		  gen_standalone.sh \
		  distribution_install.sh \
		  install_perl_modules.pl \
		  INSTALL-template.sh \
		  Dockerfile.alpine-3.6 \
		  o-saft.php

CONTRIB.zap     = zap_config.sh zap_config.xml
CONTRIB.rc      = .$(Project).tcl
# some file should get the $(Project) suffix, which is appended later
CONTRIB.complete= \
		  bash_completion \
		  dash_completion \
		  fish_completion \
		  tcsh_completion
SRC.contrib     = \
		  $(CONTRIB.complete:%=$(CONTRIB.dir)/%_$(Project)) \
		  $(CONTRIB.examples:%=$(CONTRIB.dir)/%) \
		  $(CONTRIB.post.awk:%=$(CONTRIB.dir)/%) \
		  $(CONTRIB.post:%=$(CONTRIB.dir)/%) \
		  $(CONTRIB.misc:%=$(CONTRIB.dir)/%) \
		  $(CONTRIB.zap:%=$(CONTRIB.dir)/%) \
		  $(CONTRIB.rc:%=$(CONTRIB.dir)/%)

SRC.make        = Makefile
SRC.misc        = README CHANGES
SRC.inst        = contrib/INSTALL-template.sh

# documentation files
DOC.dir         = docs
DOC.src         = o-saft.odg o-saft.pdf
SRC.doc         = $(DOC.src:%=$(DOC.dir)/%)
WEB.dir         = doc/img
WEB.src         = \
		  img.css \
		  O-Saft_cipherCLI.png \
		  O-Saft_cmd_GUI.png \
		  O-Saft_optGUI.png \
		  O-Saft_altnameCLI.png \
		  O-Saft_filterGUI.png \
		  O-Saft_protGUI.png \
		  O-Saft_altnameGUI.png \
		  O-Saft_cmd_GUI-0.png \
		  O-Saft_helpGUI-0.png \
		  O-Saft_vulnsCLI.png \
		  O-Saft_checkGUI.png \
		  O-Saft_cmd_GUI--docker.png \
		  O-Saft_helpGUI-1.png \
		  O-Saft_vulnsGUI.png \
		  O-Saft_CLI__faked.txt
SRC.web         = $(WEB.src:%=$(WEB.dir)/%)


# generated files
TMP.dir         = /tmp/$(Project)
GEN.html        = $(Project).html
GEN.cgi.html    = $(Project).cgi.html
GEN.wiki        = $(Project).wiki
GEN.pod         = $(Project).pod
GEN.src         = $(Project)-standalone.pl
GEN.inst        = INSTALL.sh
GEN.tags        = tags

GEN.tgz         = $(Project).tgz
GEN.tmptgz      = $(TMP.dir)/$(GEN.tgz)

# summary variables
ALL.osaft       = $(SRC.pl)  $(SRC.tcl) $(CHK.pl)  $(SRC.pm) $(SRC.sh) $(SRC.txt) $(SRC.rc) $(SRC.docker)
SRC.exe         = $(SRC.pl)  $(SRC.tcl) $(CHK.pl)  $(DEV.pl) $(SRC.sh)
ALL.exe         = $(SRC.exe) $(SRC.cgi) $(GEN.src) $(SRC.docker)
ALL.test        = $(SRC.test)
ALL.contrib     = $(SRC.contrib)
ALL.pm          = $(SRC.pm)
ALL.gen         = $(GEN.src) $(GEN.pod) $(GEN.html) $(GEN.cgi.html) $(GEN.inst) $(GEN.tags)
ALL.tgz         = \
		  $(SRC.make) \
		  $(ALL.exe) \
		  $(ALL.pm) \
		  $(ALL.test) \
		  $(SRC.txt) \
		  $(SRC.rc) \
		  $(SRC.misc) \
		  $(SRC.doc) \
		  $(ALL.gen) \
		  $(ALL.contrib)
ALL.critic      = $(ALL.pm)  $(SRC.pl) $(CHK.pl)

# internal used tools (paths hardcoded!)
ECHO            = /bin/echo -e
MAKE            = $(MAKE_COMMAND)
EXE.bench       = test/o-saft_bench
EXE.test.bunt   = test/test-bunt.pl.txt
EXE.test.cgi    = test/test-o-saft.cgi.sh
EXE.single      = contrib/gen_standalone.sh
EXE.pl          = $(SRC.pl)
#                   SRC.pl is used for generating a couple of data

# INSTALL.sh must not contain duplicate files, hence the variable's content
# is sorted using make's built-in sort which removes duplicates
_INST.contrib   = $(sort $(ALL.contrib))
_INST.osaft     = $(sort $(ALL.osaft))
_INST.text      = generated from Makefile 1.10
EXE.install     = sed   -e 's@CONTRIB_INSERTED_BY_MAKE@$(_INST.contrib)@' \
			-e 's@OSAFT_INSERTED_BY_MAKE@$(_INST.osaft)@' \
			-e 's@INSERTED_BY_MAKE@$(_INST.text)@'

# internal variables
# MFLAGS        = options passed to make;    # provided by make
# MAKEOVERRIDES = arguments passed to make;  # provided by make
_TAB            = \\011
_NL             = \\012
_CR             = \\015

_TODAY_         = $(shell date +m%d)

# internal help
# (for details about the commands, please see "HACKER's HELP" above)
_HELP_INFO_     = \# Name          | Description/Content
_HELP_LINE_     = \#---------------+------------------------------------------------------------
_HELP_HEADER_   = $(_HELP_LINE_)\012$(_HELP_INFO_)\012$(_HELP_LINE_)
_HELP_USAGE_    = **USAGE:  $(MAKE) $($@) '$($@)=your-query'

# tools used to gather information from herein
EXE.list        = awk '/^[_a-zA-Z][_a-zA-Z.]* *=.*/{print $$1}'
EXE.eval        = awk -F=    '/^HELP-_/{print "_f-"$$1}/^HELP-[^ _]/{sub(/HELP-/,"");print "f-"$$1}'
EXE.help        = sed -n -e 's/^HELP-_[^=]*=[" ]*\([^"]*\)"*/		\1/p' \
			 -e 's/^HELP-\(.*\)[	 ]*=[" ]*\([^"]*\)"*/ \1    - \2/p'
EXE.macro       = sed -n -e '/^$($@)[ 	:+]*=/{' \
			 -e ':m' -e 'p' -e '/\\$$/{' -e 'n' -e 'bm' -e '}' -e '}'
EXE.pmacro      = sed -n -e '/.*$($@).*[        :+]*=/{' \
			 -e ':m' -e 'p' -e '/\\$$/{' -e 'n' -e 'bm' -e '}' -e '}'
EXE.target      = sed -n -e ':t' -e '/^[^:\043]*$($@)[^:\043]*[:]/{' \
			 -e ':c' -e 'p' -e 'n' -e '/^       /bc' -e 'bt' -e '}'
EXE.wordperline = tr -s " $(_TAB)" "$(_NL)$(_NL)"
#               # must use " so that make's variables are evaluated correctly
EXE.wordperline = awk '{for(i=1;i<=NF;i++){printf("\t\t  %s\n",$$i)}}'

#_____________________________________________________________________________
#___________________________________________________________ default target __|

default:
	@$(TARGET_VERBOSE)
	@$(ECHO) "$(_HELP_HEADER_)"
	@$(EXE.help) $(MAKEFILE)
	@echo "$(_HELP_LINE_)"
	@echo "# see also: $(MAKE) doc"
	@echo ""

#_____________________________________________________________________________
#__________________________________________________________________ targets __|

HELP-_known     = _______________________________________ well known targets _
HELP-all        = does nothing; alias for help
HELP-clean      = remove all generated files '$(ALL.gen)'
HELP-install    = install tool in '$(INSTALL.dir)' using INSTALL.sh, $(INSTALL.dir) must not exist
HELP-uninstall  = remove installtion directory '$(INSTALL.dir)' completely

$(INSTALL.dir):
	@$(TARGET_VERBOSE)
	mkdir $(_INSTALL_FORCE_) $(INSTALL.dir)

all:    default

clean:
	@$(TARGET_VERBOSE)
	-rm -r --interactive=never $(ALL.gen)
clear:  clean

install: $(GEN.inst) $(INSTALL.dir)
	@$(TARGET_VERBOSE)
	$(GEN.inst) $(INSTALL.dir) \
	    && $(SRC.pl) --no-warning --tracearg +quit > /dev/null
install-f: _INSTALL_FORCE_ = -p
install-f: install

uninstall:
	@$(TARGET_VERBOSE)
	-rm -r --interactive=never $(INSTALL.dir)

.PHONY: all clean install install-f uninstall

variables       = \$$(variables)
#               # define literal string $(variables) for "make doc"
HELP-_project   = ____________________________________ targets for $(Project) _
HELP-help       = print overview of all targets
HELP-doc        = same as help, but evaluates '$(variables)'
HELP-pl         = generate '$(SRC.pl)' from managed source files
HELP-cgi        = generate HTML page for use with CGI '$(GEN.cgi.html)'
HELP-pod        = generate POD format help '$(GEN.pod)'
HELP-html       = generate HTML format help '$(GEN.html)'
HELP-wiki       = generate mediawiki format help '$(GEN.wiki)'
HELP-tar        = generate '$(GEN.tgz)' from all source
HELP-tmptar     = generate '$(GEN.tmptgz)' from all sources
HELP-cleantar   = remove '$(GEN.tgz)'
HELP-cleantmp   = remove '$(TMP.dir)'
HELP-clean-all  = remove '$(GEN.tgz) $(ALL.gen)'
HELP-install-f  = install tool in '$(INSTALL.dir)' using INSTALL.sh, $(INSTALL.dir) may exist

OPT.single = --s

# alias targets
help:   default
pl:     $(SRC.pl)
cgi:    $(GEN.cgi.html)
pod:    $(GEN.pod)
html:   $(GEN.html)
wiki:   $(GEN.wiki)
standalone: $(GEN.src)
tar:    $(GEN.tgz)
GREP_EDIT = 1.10
tar:     GREP_EDIT = 1.10
tmptar:  GREP_EDIT = something which hopefully does not exist in the file
tmptar: $(GEN.tmptgz)
tmptgz: $(GEN.tmptgz)
cleantar:   clean-tar
cleantgz:   clean-tar
cleantmp:   clean-tmp
cleartar:   clean-tar
cleartgz:   clean-tar
cleartmp:   clean-tmp
clear-all:  clean-tar clean
clean-all:  clean-tar clean
tgz:    tar
tar:    OPT.single =
tgz:    OPT.single =
tmptar: OPT.single =
tmptgz: OPT.single =

.PHONY: pl cgi pod html wiki standalone tar tmptar tmptgz cleantar cleantmp

clean-tmp:
	@$(TARGET_VERBOSE)
	rm -rf $(TMP.dir)
clean-tar:
	@$(TARGET_VERBOSE)
	rm -rf $(GEN.tgz)
clean-tgz: clean-tar

# targets for generation
$(TMP.dir)/Net $(TMP.dir)/OSaft $(TMP.dir)/OSaft/Doc $(TMP.dir)/$(CONTRIB.dir) $(TMP.dir)/$(TEST.dir):
	@$(TARGET_VERBOSE)
	mkdir -p $@

# cp fails if SRC.pl is read-only, hence we remove it; it is generated anyway
$(SRC.pl): $(DEV.pl)
	@$(TARGET_VERBOSE)
	rm -f $@
	cp $< $@

$(GEN.src):  $(EXE.single) $(SRC.pl) $(ALL.pm)
	@$(TARGET_VERBOSE)
	$(EXE.single) $(OPT.single)

$(GEN.pod):  $(SRC.pl) $(OSD.pm) $(SRC.txt)
	@$(TARGET_VERBOSE)
	$(SRC.pl) --no-rc --no-warning --help=gen-pod  > $@

$(GEN.wiki): $(SRC.pl) $(OSD.pm) $(SRC.txt)
	@$(TARGET_VERBOSE)
	$(SRC.pl) --no-rc --no-warning --help=gen-wiki > $@

$(GEN.html): $(SRC.pl) $(OSD.pm) $(SRC.txt)
	@$(TARGET_VERBOSE)
	$(SRC.pl) --no-rc --no-warning --help=gen-html > $@

$(GEN.cgi.html): $(SRC.pl) $(OSD.pm) $(SRC.txt)
	@$(TARGET_VERBOSE)
	$(SRC.pl) --no-rc --no-warning --help=gen-cgi  > $@

$(GEN.inst): $(SRC.inst) Makefile
	@$(TARGET_VERBOSE)
	$(EXE.install) $(SRC.inst) > $@
	chmod +x $@

$(GEN.tgz)--to-noisy: $(ALL.tgz)
	@$(TARGET_VERBOSE)
	@grep -q '$(GREP_EDIT)' $? \
	    && echo "file(s) being edited or with invalid SID" \
	    || echo tar zcf $@ $^

# special target to check for edited files; it only checks the
# source files of the tool (o-saft.pl) but no other source files
_notedit: $(SRC.exe) $(SRC.pm) $(SRC.rc) $(SRC.txt)
	@$(TARGET_VERBOSE)
	@grep -q '$(GREP_EDIT)' $? \
	    && echo "file(s) being edited or with invalid SID" \
	    && exit 1 \
	    || echo "# no edits"

.PHONY: _notedit

#$(GEN.tgz): _notedit $(ALL.tgz)   # not working properly
#     tar: _notedit: Funktion stat failed: file or directory not found
$(GEN.tgz): $(ALL.tgz)
	@$(TARGET_VERBOSE)
	tar zcf $@ $^

$(GEN.tmptgz): $(ALL.tgz)
	@$(TARGET_VERBOSE)
	tar zcf $@ $^

#_____________________________________________________________________________
#______________________________________________________ targets for testing __|

HELP-_test      = ______________________________________ targets for testing _
HELP-bench      = call '$(EXE.bench)' for some benchmarks
HELP-bench.log  = call '$(EXE.bench)' and save result in '$(BENCH.times)'
HELP-test.bunt  = test '$(CONTRIB.dir)/bunt.pl' with sample file
HELP-test.cgi   = test invalid IPs to be rejected by '$(SRC.cgi)'
HELP-test-warnings = test **WARNING messages of '$(SRC.pl)'
HELP-test-warnings.log = test **WARNING messages of '$(SRC.pl)' and compare with previous one
HELP-test       = TBD - comming soon

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

# testing warning messages
# TODO: internal description for targets
warning.2:
	@echo "TODO: testing openssl returning error"
warning.4:
	@echo "TODO: testing missing IO/Socket/SSL.pm"
warning.6:
	@echo "TODO: testing missing Net/DNS.pm"
warning.7:
	@echo "TODO: testing missing Time/Local.pm"
warning.8:
	@echo "TODO: testing missing Net/SSLhello.pm"
warning.9:
	@echo "TODO: testing missing Net/SSLinfo.pm"
warning.13:
	@echo "TODO: testing missing Net::SSLeay.pm"
warning.120:
	@echo "TODO: testing ancient perl"
warning.121:
	@echo "TODO: testing ancient module"
warning.122:
	@echo "TODO: testing ancient Net::SSLeay"
warning.123:
	@echo "TODO: testing ancient IO::Socket"
warning.124:
	@echo "TODO: testing ancient IO::Socket::SSL"
warning.125:
	@echo "TODO: testing openssl < 1.0.0"
warning.126:
	@echo "TODO: testing missing ALPN functionality"
warning.127:
	@echo "TODO: testing Net::SSLeay < 1.56 (ALPN disabled)"
warning.128:
	@echo "TODO: testing openssl < 1.0.2 (ALPN disabled)"
warning.129:
	@echo "TODO: testing missing NPN functionality"
warning.130:
	@echo "TODO: testing Net::SSLeay < 1.46 (ALPN disabled)"
warning.131:
	@echo "TODO: testing openssl < 1.0.1 (ALPN disabled)"
warning.135:
	@echo "TODO: testing Net::SSLeay < 1.49"

warning.41: $(SRC.pl)
	@$(TARGET_VERBOSE)
	-$(SRC.pl) s_client                            +quit | grep 41
warning.42:
	@echo "TODO: testing invalid host-like argument"
warning.43: $(SRC.pl)
	@$(TARGET_VERBOSE)
	echo "--cfg_cmd=quit=existing_command" > /tmp/tmprc
	-$(SRC.pl) --rc=/tmp/tmprc                     +quit | grep 43
	@-rm /tmp/tmprc
warning.44: $(SRC.pl)
	@$(TARGET_VERBOSE)
	-$(SRC.pl) +zlib +lzo +open_pgp +fallback      +quit | grep 44
warning.47: $(SRC.pl)
	@$(TARGET_VERBOSE)
	-$(SRC.pl) +info +cn                    unknown-host | grep 47
warning.48: $(SRC.pl)
	@$(TARGET_VERBOSE)
	-$(SRC.pl) +check +cn                   unknown-host | grep 48
warning.49: $(SRC.pl)
	@$(TARGET_VERBOSE)
	-$(SRC.pl) +unknown_command                    +quit | grep 49
warning.52: $(SRC.pl)
	@$(TARGET_VERBOSE)
	echo "--option=-with_trailing_spaces  " > /tmp/tmprc
	-$(SRC.pl) --rc=/tmp/tmprc                     +quit | grep 52
	@-rm /tmp/tmprc
warning.53: $(SRC.pl)
	@$(TARGET_VERBOSE)
	-$(SRC.pl) --capath="/path with spaces"        +quit | grep 53
warning.54: $(SRC.pl)
	@$(TARGET_VERBOSE)
	-$(SRC.pl) --legacy=unknown_legacy             +quit | grep 54
warning.55: $(SRC.pl)
	@$(TARGET_VERBOSE)
	-$(SRC.pl) --format=unknown_format             +quit | grep 55
warning.56: $(SRC.pl)
	@$(TARGET_VERBOSE)
	-$(SRC.pl) --range=unknown_cipher-range        +quit | grep 56
warning.57: $(SRC.pl)
	@$(TARGET_VERBOSE)
	-$(SRC.pl) --ciphercurves=unknown_cipher-curve +quit | grep 57
warning.70:
	@echo "TODO: testing missing RC-file"
warning.71: $(SRC.pl)
	@$(TARGET_VERBOSE)
	echo "--cfg_unknown=dummy=dummy" > /tmp/tmprc
	-$(SRC.pl) --rc=/tmp/tmprc                     +quit | grep 71
	@-rm /tmp/tmprc
warning.72: $(SRC.pl)
	@$(TARGET_VERBOSE)
	echo "--cfg_cmd=ignored=dummy" > /tmp/tmprc
	-$(SRC.pl) --cfg_cmd=/tmp/tmprc                +quit | grep 72
	@-rm /tmp/tmprc
warning.73: $(SRC.pl)
	@$(TARGET_VERBOSE)
	echo "--cfg_cmd=invalid_default_command=default" > /tmp/tmprc
	-$(SRC.pl) --rc=/tmp/tmprc                     +quit | grep 73
	@-rm /tmp/tmprc
warning.74: $(SRC.pl)
	@$(TARGET_VERBOSE)
	echo "--cfg_cmd=dummy=cn unknown_command" > /tmp/tmprc
	-$(SRC.pl) --rc=/tmp/tmprc                     +quit | grep 74
	@-rm /tmp/tmprc
warning.76:
	@echo "TODO: testing score sitting will be removed in future"
warning.111: $(SRC.pl)
	-@$(TARGET_VERBOSE)
	@echo "TODO: testing missing Net/DNS.pm"
	-$(SRC.pl) --mx --nodns                        +quit | grep 111
warning.112: $(SRC.pl)
	@$(TARGET_VERBOSE)
	@echo "TODO: testing missing Time/Local.pm (+sts_expired)"
	-$(SRC.pl) +sts_expired                        +quit | grep 112
warning.140: $(SRC.pl)
	@$(TARGET_VERBOSE)
	-$(SRC.pl) +cipherraw --dtlsv1                 +quit | grep 140
warning.141: $(SRC.pl)
	@$(TARGET_VERBOSE)
	@echo "TODO: testing wrong SSL version"
	#-$(SRC.pl) +cipherraw --dtlsv9                 +quit | grep 141
warning.143: $(SRC.pl)
	@echo "TODO: testing SSL version not supported by Net::SSLeay"
warning.144:
	@echo "TODO: testing missing openssl support for -alpn|-npn"
warning.145:
	@echo "TODO: testing missing openssl support for -alpn|-npn"
warning.146:
	@echo "TODO: testing missing openssl -tlsextdebug option"
warning.147:
	@echo "TODO: testing missing openssl executable in Net::SSLinfo"
	#$(SRC.pl) --openssl=/does/not/exist           +quit | grep 147
warning.148: $(SRC.pl)
	@$(TARGET_VERBOSE)
	@echo "TODO: testing missing openssl executable"
	-$(SRC.pl) --openssl=/does/not/exist           +quit | grep 148
warning.149: $(SRC.pl)
	@$(TARGET_VERBOSE)
	-$(SRC.pl) --openssl=/does/not/exist           +quit | grep 149

ALL.warnings    = \
	warning.41 warning.43 warning.44 warning.47 warning.48 warning.49 \
	warning.52 warning.53 warning.54 warning.55 warning.56 \
	warning.71 warning.72 warning.73 warning.74 \
	warning.140 warning.148 warning.149

test-warnings: $(ALL.warnings)

# $(_WARNING.log) calls "make -s" to avoid printing of executed commands
_WARNING.log    = $(TEST.dir)/test-warnings-$(_TODAY_).log
$(_WARNING.log):
	@$(MAKE) -s $(ALL.warnings) > $@

# target should create a new logfile, then compare it with the curennt one
# if current logfile is missing use newly created one: "mv ... || cp ..."
# this avoid errors whe the file is missing
# if the diff returns nothing, mv newlycreated logfile to target, otherwise
# restore previous one
test-warnings.log: $(_WARNING.log) $(SRC.pl)
	-mv $(TEST.dir)/$@ $@-last \
	 || cp $(_WARNING.log) $@-last
	diff   $@-last $(_WARNING.log) \
	 && mv $(_WARNING.log) $(TEST.dir)/$@ && rm $@-last \
	 || mv $@-last     $(TEST.dir)/$@ 
	@ls -l  $(TEST.dir)/$@

.PHONY: test-warnings.log

# internal information
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
#_________________________________________________ targets for code quality __|

HELP-_qa        = _________________________________ targets for code quality _
HELP-critichelp = print more details about  critic-*  targets
HELP-critic     = check files with perlcritic
HELP-critic345  = check files with perlcritic for severity 3,4,5 using test/critic_345.sh
HELP-tags       = generate tags file for vi
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

$(GEN.tags): $(SRC.pl) $(ALL.pm) $(CHK.pl) $(SRC.cgi) $(SRC.tcl) Makefile
	ctags $^

#_____________________________________________________________________________

HELP-_special   = ___________ any target may be used with following suffixes _
HELP--v         = verbose: print target and newer dependencies
HELP--vv        = verbose: print target and all dependencies

# verbose command
#       TARGET_VERBOSE  is the string to be printed in verbose mode
#                       it is epmty by default
#       TARGET_VERBOSE  can be set as environment variable, or used on command
#                       line when calling make
#                       it is also used internal for the -v targets, see below
# examples:
#  TARGET_VERBOSE = \# --Target: $@--
#  TARGET_VERBOSE = \# --Target: $@: newer dependencies: $? --
#  TARGET_VERBOSE = \# --Target: $@: all dependencies: $^ --

# verbose targets
%-v: TARGET_VERBOSE=echo "\# $@: $?"
%-v: %
	@echo "" # need at least one command for target execution

%-vv: TARGET_VERBOSE=echo "\# $@: $^"
%-vv: %
	@echo ""

# the traditional way, when target-dependent variables do not work
#%-v:
#	@$(MAKE) $(MFLAGS) $(MAKEOVERRIDES) $* 'TARGET_VERBOSE=# $$@: $$?'
#
#%-vv:
#	@$(MAKE) $(MFLAGS) $(MAKEOVERRIDES) $* 'TARGET_VERBOSE=# $$@: $$^'

#_____________________________________________________________________________
#_____________________________________________________________ help targets __|

HELP-_help      = __________________________ targets for help about Makefile _
HELP-list       = list all macro names (alias: vars)
HELP-e-MACRO    = show content of MACRO expanded (all in one line)
HELP-s-MACRO    = show content of MACRO expanded (one word per line)
HELP-m-MACRO    = show definition of MACRO as is --exact macro match
HELP-p-MACRO    = show all definitions of MACRO as is --macro pattern match
HELP-t-TARGET   = show TARGET --exact target match

#dbx _isempty:  @echo "# target: $($@) - $($($@))."
# NOTE: following target is adapted to be use in echo, show, macro and target
#       targets, hence the target name must be recursively evaluated, that's
#       why we use  $($($@)) instead of $($@)
_notempty:
	@if [ '$($($@))' = '' ]; then \
	    $(ECHO) "$(HELP-$($@))"; \
	    $(ECHO) "$(_HELP_USAGE_)"; \
	    exit 1; \
	fi;
	@$(ECHO) "$(_HELP_HEADER_)"

_line:
	@echo ""
	@$(ECHO) "$(_TAB)$(_TAB)$($($@))"

.PHONY: _notempty _line

list:
	@$(TARGET_VERBOSE)
	@$(EXE.list) $(MAKEFILE)
vars: list

eval:
	@$(TARGET_VERBOSE)
	@$(ECHO) "$($@)$(_TAB)$(_TAB)- $(HELP-$($@))"

echo:
	@$(TARGET_VERBOSE)
	@$(ECHO) '$($($@))'

show: _notempty=show
show: _notempty
	@$(TARGET_VERBOSE)
	@$(ECHO) '$($@) = '
	@$(ECHO) '$($($@))' | $(EXE.wordperline)

macro: _notempty=macro
macro: _notempty
	@$(TARGET_VERBOSE)
	@$(EXE.macro) $(MAKEFILE)
makro: macro

pmacro: _notempty=pmacro
pmacro: _notempty
	@$(TARGET_VERBOSE)
	@$(EXE.pmacro) $(MAKEFILE)

target: _notempty=target
target: _notempty
	@$(TARGET_VERBOSE)
	@$(EXE.target) $(MAKEFILE)

doc:
	@$(TARGET_VERBOSE)
	@$(MAKE) -s e-_HELP_HEADER_ `$(EXE.eval) $(MAKEFILE)`

# following rules are shortcuts for the above targets
e-%:
	@$(MAKE) -s echo=$* echo
f-%:
	@$(MAKE) -s eval=$* eval
_f-%:
	@$(MAKE) -s _line=$* _line
s-%:
	@$(MAKE) -s show=$* show
m-%:
	@$(MAKE) -s macro=$* macro
p-%:
	@$(MAKE) -s pmacro=$* pmacro
t-%:
	@$(MAKE) -s target=$* target

.PHONY: list vars eval echo show macro pmacro target help doc default

