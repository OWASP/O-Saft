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
#?       Requires GNU Make > 2.0.
#?       Requires GNU sed for generating (target) INSTALL.sh.
#?
# TODO: move complete documentation to Makefile.help
# HACKER's INFO
#       This  Makefile  uses mainly  make's built-in variables (aka macros) and
#       targets. None of them are disabled explicitly. Therefore some behaviour
#       may depend on the local make configuration.
#
#        Note: macro is a synonym for variable in makefiles.
#        Note: macro definitions in makefiles must not be sequential!
#
#    Remember make's automatic variables:
#           $@    - target (file)
#           $+    - all dependencies of the target
#           $^    - all dependencies of the target (without duplicates)
#           $<    - first dependency of the target
#           $?    - dependencies newer than the target
#           $|    - "orde-only" dependencies
#           $*    - matching files of the rule
#           $%    - target (archive) member name (rarely used)
#        Use of $$ avoids evaluating $ .
#
#    Variable, macro names
#        General rules for our variable names in this Makefile:
#           * variable names consist only of characters a-zA-Z0-9_.
#           * variable names start with upper case letters or _
#
#        Internal variables:
#           _SID        - version in project's Makefile
#           _SID.*      - version in included makefiles
#           _MYSELF.*   - name of the Makefile itself
#
#        The _SID* variables are used to check if sub-makefiles were included.
#        More variables and targets are defined in following included files:
#           Makefile.help
#           t/Makefile
#           t/Makefile.inc
#        Where  t/Makefile  may include more files.
#        Each of the included files may be used independently with  -f  option,
#        for example::
#           make -f Makefile.help
#           make -f t/Makefile
#
#        Following name prefixes are used:
#           SRC         - defines a source file
#           GEN         - defines a genarted file
#           EXE         - defines a tools to be used
#           ALL         - defines summary variables
#           TEST        - something related to the t/ directory
#           CONTRIB     - something related to the contrib/ directory
#           CRITIC      - something related to percritic targets
#           _           - names of internal (helper) variables (they are not
#                         intended to be overwritten on command line)
#           HELP        - defines texts to be used in  help  and  doc  target
#
#        Following names are used, which potentially conflict with make itself:
#           ECHO        - echo command
#           MAKE        - make command
#           MAKEFILE    - Makefile (i.g. myself, but may be redifined)
#
#        Notes about some special variables:
#           ALL.src     - list of all sources to be distributed
#           ALL.tgz     - same as ALL.src but all sources prefixed with O-Saft/
#           ALL.test    - list of all sources used for testing the project
#           ALL.tests   - list of all targets for testing
#           ALL.includes - dynamically generated list of all included makefiles
#           ALL.Makefiles - static list of all source makefiles of the project
#
#        In general no quotes are used around texts in variables. Though, it is
#        sometimes necessary to use quotes  to force correct evaluation of used
#        variables in the text (mainly in target actions).
#
# HACKER's HELP
#        For details, in particular the syntax of the  HELP-*  macros used here
#        please see Makefile.help .
#
#? VERSION
#?      @(#) Makefile 1.37 18/10/06 23:03:02
#?
#? AUTHOR
#?      21-dec-12 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

_SID            = 1.37
    # define our own SID as variable, if needed ...

ALL.includes   := Makefile
                # must be  :=  to avoid overwrite after includes
                # each $(TEST.dir)/Makefile* will add itself to ALL.includes

MAKEFLAGS      += --no-builtin-variables --no-builtin-rules
.SUFFIXES:

first-target-is-default: default

MAKEFILE    = Makefile
# define variable for myself, it allows to use some targets within other files
# Note  that  $(MAKEFILE)  is used where any Makefile is possible and  Makefile
#       is used when exactly this file is meant. $(ALL.Makefiles) is used, when
#       all Makefiles are needed.

#_____________________________________________________________________________
#________________________________________________________________ variables __|

Project         = o-saft
ProjectName     = O-Saft
INSTALL.dir     = /usr/local/$(Project)

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
		  $(Project)-usr.pm
SRC.pm          = \
		  osaft.pm \
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

SRC.make        = Makefile
SRC.misc        = README CHANGES
SRC.inst        = $(CONTRIB.dir)/INSTALL-template.sh

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
		  build_openssl.sh \
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
ALL.contrib     = $(SRC.contrib)

# test files
TEST.dir        = t
TEST.logdir     = $(TEST.dir)/log
TEST.do         = SSLinfo.pl \
                  o-saft_bench.sh \
                  critic_345.sh \
                  test-bunt.pl.txt
CRITIC.rc       = .perlcriticrc
SRC.test        = \
                  $(TEST.do:%=$(TEST.dir)/%) \
                  $(CRITIC.rc:%=$(TEST.dir)/%)
ALL.test        = $(SRC.test)

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
ALL.doc         = $(SRC.doc) $(SRC.web)

# generated files
TMP.dir         = /tmp/$(Project)
GEN.html        = $(Project).html
GEN.cgi.html    = $(Project).cgi.html
GEN.text        = $(Project).txt
GEN.wiki        = $(Project).wiki
GEN.pod         = $(Project).pod
GEN.src         = $(Project)-standalone.pl
GEN.inst        = INSTALL.sh
GEN.tags        = tags

GEN.tgz         = $(Project).tgz
GEN.tmptgz      = $(TMP.dir)/$(GEN.tgz)

# summary variables
SRC.exe         = $(SRC.pl)  $(SRC.tcl) $(CHK.pl)  $(DEV.pl) $(SRC.sh)
ALL.Makefiles   = \
		  $(SRC.make) Makefile.help \
		  $(TEST.dir)/Makefile          $(TEST.dir)/Makefile.inc \
		  $(TEST.dir)/Makefile.opt      $(TEST.dir)/Makefile.cmds \
		  $(TEST.dir)/Makefile.ext      $(TEST.dir)/Makefile.exit \
		  $(TEST.dir)/Makefile.cgi      $(TEST.dir)/Makefile.tcl \
		  $(TEST.dir)/Makefile.warnings $(TEST.dir)/Makefile.misc \
		  $(TEST.dir)/Makefile.critic   $(TEST.dir)/Makefile.template \
		  $(TEST.dir)/Makefile.FQDN
# NOTE: sequence in ALL.Makefiles is important, for example when used in target doc
ALL.osaft       = $(SRC.pl)  $(SRC.tcl) $(CHK.pl)  $(SRC.pm) $(SRC.sh) $(SRC.txt) $(SRC.rc) $(SRC.docker)
ALL.exe         = $(SRC.exe) $(SRC.cgi) $(GEN.src) $(SRC.docker)
ALL.test        = $(SRC.test)
ALL.contrib     = $(SRC.contrib)
ALL.pm          = $(SRC.pm)
ALL.gen         = $(GEN.src) $(GEN.pod) $(GEN.html) $(GEN.cgi.html) $(GEN.inst) $(GEN.tags)
ALL.src         = \
		  $(ALL.exe) \
		  $(ALL.pm) \
		  $(SRC.txt) \
		  $(SRC.rc) \
		  $(SRC.misc) \
		  $(SRC.doc) \
		  $(ALL.gen) \
		  $(ALL.Makefiles) \
		  $(ALL.test) \
		  $(ALL.contrib)
ALL.tgz         = $(ALL.src:%=O-Saft/%)

# internal used tools (paths hardcoded!)
ECHO            = /bin/echo -e
MAKE            = $(MAKE_COMMAND)
EXE.single      = contrib/gen_standalone.sh
EXE.docker      = o-saft-docker
EXE.pl          = $(SRC.pl)
#                   SRC.pl is used for generating a couple of data

# INSTALL.sh must not contain duplicate files, hence the variable's content
# is sorted using make's built-in sort which removes duplicates
_INST.contrib   = $(sort $(ALL.contrib))
_INST.osaft     = $(sort $(ALL.osaft))
_INST.text      = generated from Makefile 1.37
EXE.install     = sed   -e 's@INSTALLDIR_INSERTED_BY_MAKE@$(INSTALL.dir)@' \
			-e 's@CONTRIB_INSERTED_BY_MAKE@$(_INST.contrib)@' \
			-e 's@OSAFT_INSERTED_BY_MAKE@$(_INST.osaft)@' \
			-e 's@INSERTED_BY_MAKE@$(_INST.text)@'

# generate targets to print HELP texts
_HELP.targets   = $(shell $(EXE.eval) $(ALL.Makefiles))

#_____________________________________________________________________________
#___________________________________________________________ default target __|

default:
	@$(TARGET_VERBOSE)
	@$(ECHO) "$(_HELP_HEADER_)"
	@$(EXE.help) $(ALL.Makefiles)
	@echo "$(_HELP_LINE_)"
	@echo "# see also: $(MAKE) doc"
	@echo ""

doc:
	@$(TARGET_VERBOSE)
	@$(MAKE) -s e-_HELP_HEADER_ $(_HELP.targets)

#_____________________________________________________________________________
#__________________________________________________________________ targets __|

HELP-_known     = _______________________________________ well known targets _
HELP-all        = does nothing; alias for help
HELP-clean      = remove all generated files '$(ALL.gen)'
HELP-release    = generate signed '$(GEN.tgz)' from sources
HELP-install    = install tool in '$(INSTALL.dir)' using INSTALL.sh, $(INSTALL.dir) must exist
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
	sh $(GEN.inst) $(INSTALL.dir) \
	    && perl $(SRC.pl) --no-warning --tracearg +quit > /dev/null
install-f: _INSTALL_FORCE_ = -p
install-f: install

uninstall:
	@$(TARGET_VERBOSE)
	-rm -r --interactive=never $(INSTALL.dir)

_RELEASE    = $(shell perl -nle '/^\s*STR_VERSION/ && do { s/.*?"([^"]*)".*/$$1/;print }' $(SRC.pl))
release: $(GEN.tgz)
	mkdir -p $(_RELEASE)
	sha256sum $(GEN.tgz) > $(_RELEASE)/$(GEN.tgz).sha256
	@cat $(_RELEASE)/$(GEN.tgz).sha256
	gpg --local-user o-saft -a --detach-sign $(GEN.tgz)
	gpg --verify $(GEN.tgz).asc $(GEN.tgz)
	mv $(GEN.tgz).asc $(_RELEASE)/
	mv $(GEN.tgz)     $(_RELEASE)/
	@echo "# don't forget:"
	@echo "#   # change digest: sha256:... in README; upload to github"
	@echo "#   # change digest: sha256:... in Dockerfile; upload to github"
	@echo "#   make docker"
	@echo "#   make test.docker"
	@echo "#   make docker.push"
# TODO: check if files are edited or missing


.PHONY: all clean install install-f uninstall release doc default

variables       = \$$(variables)
#               # define literal string $(variables) for "make doc"
HELP-_project   = ____________________________________ targets for $(Project) _
HELP-help       = print overview of all targets
HELP-doc        = same as help, but evaluates '$(variables)'
HELP-pl         = generate '$(SRC.pl)' from managed source files
HELP-cgi        = generate HTML page for use with CGI '$(GEN.cgi.html)'
HELP-pod        = generate POD format help '$(GEN.pod)'
HELP-html       = generate HTML format help '$(GEN.html)'
HELP-text       = generate plain text  help '$(GEN.text)'
HELP-wiki       = generate mediawiki format help '$(GEN.wiki)'
HELP-tar        = generate '$(GEN.tgz)' from all source prefixed with O-Saft/
HELP-tmptar     = generate '$(GEN.tmptgz)' from all sources without prefix
HELP-docker     = generate local docker image (release version) and add updated files
HELP-docker-dev = generate local docker image (development version)
HELP-docker-push= install local docker image at Docker repository
HELP-cleantar   = remove '$(GEN.tgz)'
HELP-cleantmp   = remove '$(TMP.dir)'
HELP-clean.all  = remove '$(GEN.tgz) $(ALL.gen)'
HELP-install-f  = install tool in '$(INSTALL.dir)' using INSTALL.sh, $(INSTALL.dir) may exist

OPT.single = --s

# alias targets
help:   default
pl:     $(SRC.pl)
cgi:    $(GEN.cgi.html)
pod:    $(GEN.pod)
html:   $(GEN.html)
text:   $(GEN.text)
wiki:   $(GEN.wiki)
standalone: $(GEN.src)
tar:    $(GEN.tgz)
GREP_EDIT = 1.37
tar:     GREP_EDIT = 1.37
tmptar:  GREP_EDIT = something which hopefully does not exist in the file
tmptar: $(GEN.tmptgz)
tmptgz: $(GEN.tmptgz)
cleantar:   clean.tar
cleantgz:   clean.tar
cleantmp:   clean.tmp
cleartar:   clean.tar
cleartgz:   clean.tar
cleartmp:   clean.tmp
clear.all:  clean.tar clean
clean.all:  clean.tar clean
tgz:    tar
tar:    OPT.single =
tgz:    OPT.single =
tmptar: OPT.single =
tmptgz: OPT.single =

# docker target uses our own script to build a proper image
docker:
	@$(TARGET_VERBOSE)
	$(EXE.docker) -OSAFT_VERSION=$(_RELEASE) build
	$(EXE.docker) cp Dockerfile
	$(EXE.docker) cp README

docker.dev:
	@$(TARGET_VERBOSE)
	docker build --force-rm --rm \
		--build-arg "OSAFT_VM_SRC_OSAFT=https://github.com/OWASP/O-Saft/archive/master.tar.gz" \
		--build-arg "OSAFT_VERSION=$(_RELEASE)" \
		-f Dockerfile -t owasp/o-saft .

# TODO: docker.push should depend on docker, but thats not a file or target
docker.push:
	@$(TARGET_VERBOSE)
	docker push owasp/o-saft:latest

.PHONY: pl cgi pod html wiki standalone tar tmptar tmptgz cleantar cleantmp help
.PHONY: docker docker.dev docker.push

clean.tmp:
	@$(TARGET_VERBOSE)
	rm -rf $(TMP.dir)
clean.tar:
	@$(TARGET_VERBOSE)
	rm -rf $(GEN.tgz)
clean.tgz: clean.tar

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

$(GEN.pod):  $(SRC.pl) $(OSD.pm) $(USR.pm) $(SRC.txt)
	@$(TARGET_VERBOSE)
	$(SRC.pl) --no-rc --no-warning --help=gen-pod  > $@

$(GEN.text): $(SRC.pl) $(OSD.pm) $(USR.pm) $(SRC.txt)
	@$(TARGET_VERBOSE)
	$(SRC.pl) --no-rc --no-warning --help          > $@

$(GEN.wiki): $(SRC.pl) $(OSD.pm) $(USR.pm) $(SRC.txt)
	@$(TARGET_VERBOSE)
	$(SRC.pl) --no-rc --no-warning --help=gen-wiki > $@

$(GEN.html): $(SRC.pl) $(OSD.pm) $(USR.pm) $(SRC.txt)
	@$(TARGET_VERBOSE)
	$(SRC.pl) --no-rc --no-warning --help=gen-html > $@

$(GEN.cgi.html): $(SRC.pl) $(OSD.pm) $(USR.pm) $(SRC.txt)
	@$(TARGET_VERBOSE)
	$(SRC.pl) --no-rc --no-warning --help=gen-cgi  > $@

$(GEN.inst): $(SRC.inst) Makefile
	@$(TARGET_VERBOSE)
	$(EXE.install) $(SRC.inst) > $@
	chmod +x $@

$(GEN.tgz)--to-noisy: $(ALL.src)
	@$(TARGET_VERBOSE)
	@grep -q '$(GREP_EDIT)' $? \
	    && echo "file(s) being edited or with invalid SID" \
	    || echo tar zcf $@ $^

# Special target to check for edited files; it only checks the
# source files of the tool (o-saft.pl) but no other source files.
_notedit: $(SRC.exe) $(SRC.pm) $(SRC.rc) $(SRC.txt)
	@$(TARGET_VERBOSE)
	@grep -q '$(GREP_EDIT)' $? \
	    && echo "file(s) being edited or with invalid SID" \
	    && exit 1 \
	    || echo "# no edits"

.PHONY: _notedit

#$(GEN.tgz): _notedit $(ALL.src)   # not working properly
#     tar: _notedit: Funktion stat failed: file or directory not found

# .tgz is tricky:  as all members should have the directory prefixed, tar needs
# to be executed in the parent directory and use $(ALL.tgz) as members.
# The target itself is called in the current directory,  hence the dependencies
# are local to that which is $(ALL.src). Note that $(ALL.tgz) is generated from
# $(ALL.src), so it contains the same members.  Executing tar in the parent dir
# would generate the tarball ther also,  hence the tarball is specified as full
# path with $(PWD).
$(GEN.tgz): $(ALL.src)
	@$(TARGET_VERBOSE)
	cd .. && tar zcf $(PWD)/$@ $(ALL.tgz)

$(GEN.tmptgz): $(ALL.src)
	@$(TARGET_VERBOSE)
	tar zcf $@ $^

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
# Note: need at least one command for target execution
%-v: TARGET_VERBOSE=echo "\# $@: $?"
%-v: %
	@echo -n ""

%-vv: TARGET_VERBOSE=echo "\# $@: $^"
%-vv: %
	@echo -n ""

# the traditional way, when target-dependent variables do not work
#%-v:
#	@$(MAKE) $(MFLAGS) $(MAKEOVERRIDES) $* 'TARGET_VERBOSE=# $$@: $$?'
#
#%-vv:
#	@$(MAKE) $(MFLAGS) $(MAKEOVERRIDES) $* 'TARGET_VERBOSE=# $$@: $$^'

#_____________________________________________________________________________
#_____________________________________________ targets for testing and help __|

include Makefile.help
include $(TEST.dir)/Makefile
    # Note that $(TEST.dir)/Makefile includes all other Makefile.* there

