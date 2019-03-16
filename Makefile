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
#       SEE  Make:automatic variables  also.
#
#       Note: macro is a synonym for variable in makefiles.
#       Note: macro definitions in makefiles must not be sequential!
#       Use of $$ avoids evaluating $ (the macro).
#
#    Variable, macro names
#       General rules for our variable names in this Makefile:
#           * variable names consist only of characters a-zA-Z0-9_.
#           * variable names start with upper case letters or _
#
#       Internal variables:
#           _SID        - version in project's Makefile
#           _SID.*      - version in included makefiles
#           _MYSELF.*   - name of the Makefile itself (in included makefiles)
#
#       The  _SID*  variables are used to check if sub-makefiles were included.
#       More variables and targets are defined in following included files:
#           t/Makefile
#           t/Makefile.help
#           t/Makefile.inc
#       Where  t/Makefile  may include more files.
#       Each of the included files may be used independently using  -f  option,
#       for example::
#           make -f Makefile.help
#           make -f t/Makefile
#
#       Following name prefixes are used:
#           SRC         - defines a source file
#           GEN         - defines a genarted file
#           EXE         - defines a tools to be used
#           ALL         - defines summary variables
#           TEST        - something related to the t/ directory
#           CONTRIB     - something related to the contrib/ directory
#           CRITIC      - something related to percritic targets
#           _           - names of internal (helper) variables (they are not
#                         intended to be overwritten on command line)
#           HELP        - defines texts to be used in  help  and  doc  targets
#
#       Following names are used, which potentially conflict with make itself:
#           ECHO        - echo command
#           MAKE        - make command
#           MAKEFILE    - Makefile (i.g. myself, but may be redifined)
#
#       Notes about some special variables:
#           ALL.src     - list of all sources to be distributed
#           ALL.tgz     - same as ALL.src but all sources prefixed with O-Saft/
#           ALL.test    - list of all sources used for testing the project
#           ALL.tests   - list of all targets for testing
#           ALL.includes - dynamically generated list of all included makefiles
#           ALL.inc.type - list of all types of included makefiles
#           ALL.Makefiles - static list of all source makefiles of the project
#
#       In general no quotes are used around texts in variables. Though, it is
#       sometimes necessary to use quotes  to force correct evaluation of used
#       variables in the text (mainly in target actions).
#
# HACKER's HELP
#       For details, in particular the syntax of the  HELP-*  macros used here,
#       please see t/Makefile.help .
#       More details  why and how  some things are implemented are described in
#       t/Makefile.pod . "SEE Make:some text"  is used to reference to it.
#
#? VERSION
#?      @(#) Makefile 1.54 19/03/16 02:35:08
#?
#? AUTHOR
#?      21-dec-12 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

_SID            = 1.54
                # define our own SID as variable, if needed ...

ALL.includes   := Makefile
                # must be  :=  to avoid overwrite after includes
                # each $(TEST.dir)/Makefile* will add itself to ALL.includes

MAKEFLAGS       = --no-builtin-variables --no-builtin-rules
.SUFFIXES:

first-target-is-default: help

MAKEFILE        = Makefile
                # define variable for myself,  this allows to use  some targets
                # within other makefiles
                # Note that  $(MAKEFILE) is used where any Makefile is possible
                # and  Makefile  is used when exactly this file is meant.
                # $(ALL.Makefiles) is used, when all Makefiles are needed.

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
# add to SRC.pm  $(_CIPHER:%=OSaft/%)  when used
OSAFT.pm        = Ciphers.pm error_handler.pm
USR.pm          = \
		  $(Project)-dbx.pm \
		  $(Project)-man.pm \
		  $(Project)-usr.pm
SRC.pm          = \
		  osaft.pm \
		  $(NET.pm:%=Net/%)   \
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
		  cipher_check.sh \
		  critic.sh \
		  gen_standalone.sh \
		  distribution_install.sh \
		  install_openssl.sh \
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
DOC.src         = o-saft.odg o-saft.pdf o-saft-docker.pdf
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
GEN.rel         = $(Project).rel

GEN.tgz         = $(Project).tgz
GEN.tmptgz      = $(TMP.dir)/$(GEN.tgz)

# summary variables
SRC.exe         = $(SRC.pl)  $(SRC.tcl) $(CHK.pl)  $(DEV.pl) $(SRC.sh)
inc.Makefiles   = \
		  Makefile         Makefile.inc   Makefile.help  Makefile.pod \
		  Makefile.opt     Makefile.cmds  Makefile.ext   Makefile.exit \
		  Makefile.cgi     Makefile.tcl   Makefile.misc  Makefile.warnings \
		  Makefile.critic  Makefile.template   Makefile.FQDN
# NOTE: sequence in ALL.Makefiles is important, for example when used in target doc
ALL.Makefiles   = $(SRC.make) $(inc.Makefiles:%=$(TEST.dir)/%)
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

# tools for targets
ECHO            = /bin/echo -e
MAKE            = $(MAKE_COMMAND)
# some rules need to have a command, otherwise they are not evaluated
EXE.dummy       = /bin/echo -n ""

# internal used tools (paths hardcoded!)
EXE.single      = contrib/gen_standalone.sh
EXE.docker      = o-saft-docker
EXE.pl          = $(SRC.pl)
#                   SRC.pl is used for generating a couple of data

# INSTALL.sh must not contain duplicate files, hence the variable's content
# is sorted using make's built-in sort which removes duplicates
_INST.contrib   = $(sort $(ALL.contrib))
_INST.osaft     = $(sort $(ALL.osaft))
_INST.text      = generated from Makefile 1.54
EXE.install     = sed   -e 's@INSTALLDIR_INSERTED_BY_MAKE@$(INSTALL.dir)@' \
			-e 's@CONTRIB_INSERTED_BY_MAKE@$(_INST.contrib)@' \
			-e 's@OSAFT_INSERTED_BY_MAKE@$(_INST.osaft)@' \
			-e 's@INSERTED_BY_MAKE@$(_INST.text)@'

# generate f- targets to print HELP text for each target
_HELP.my_targets= $(shell $(EXE.eval) $(MAKEFILE))
_HELP.alltargets= $(shell $(EXE.eval) $(ALL.Makefiles))
_HELP.help      = $(ALL.help:%=f-%)
                # quick&dirty because each target calls make (see below)

#_____________________________________________________________________________
#___________________________________________________________ default target __|

# define header part of default target
help:     _HELP_HEAD_ = $(_HELP_RULE_)
help.all: _HELP_HEAD_ = $(_HELP_RULE_)
doc:      _HELP_HEAD_ = $(_HELP_RULE_)
doc.all:  _HELP_HEAD_ = $(_HELP_RULE_)

# define body part of default target
_help_also_           = _help_also
_help_body_           = _help_body_me
help.all: _help_body_ = _help_body_all
doc:      _help_body_ = _eval_body_me
doc.all:  _help_body_ = _eval_body_all
doc:      _help_also_ =
doc.all:  _help_also_ =

# SEE Make:.SECONDEXPANSION
.SECONDEXPANSION:

_eval_body_me:
	@$(MAKE) -s $(_HELP.my_targets)

_eval_body_all:
	@$(MAKE) -s $(_HELP.alltargets)

_help_body_me:
	@$(EXE.help) $(MAKEFILE)

_help_body_all:
	@$(EXE.help) $(ALL.Makefiles)

_help_list:
	@echo ""
	@echo "$(_HELP_LINE_)"
	@$(MAKE) $(_HELP.help)
	@echo "$(_HELP_LINE_)"

_help_also:
	@echo "# see also: $(MAKE) doc"

# ensure that target help: from this file is used and not help%
help help.all doc doc.all: _help.HEAD $$(_help_body_) _help_list $$(_help_also_)
	@$(TARGET_VERBOSE)

help.all-v help.all-vv: help.all
	@$(EXE.dummy)

.PHONY: help help.all doc doc.all

#_____________________________________________________________________________
#__________________________________________________________________ targets __|

HELP-_known     = _______________________________________ well known targets _
HELP-all        = does nothing; alias for help
HELP-clean      = remove all generated files '$(ALL.gen)'
HELP-release    = generate signed '$(GEN.tgz)' from sources
HELP-install    = install tool in '$(INSTALL.dir)' using '$(GEN.inst)', $(INSTALL.dir) must exist
HELP-uninstall  = remove installtion directory '$(INSTALL.dir)' completely

$(INSTALL.dir):
	@$(TARGET_VERBOSE)
	mkdir $(_INSTALL_FORCE_) $(INSTALL.dir)

all:    help

clean:
	@$(TARGET_VERBOSE)
	-rm -r --interactive=never $(ALL.gen)
clear:  clean

# target calls installed $(SRC.pl) to test general functionality
install: $(GEN.inst) $(INSTALL.dir)
	@$(TARGET_VERBOSE)
	$(GEN.inst) $(INSTALL.dir) \
	    && $(INSTALL.dir)/$(SRC.pl) --no-warning --tracearg +quit > /dev/null
install-f: _INSTALL_FORCE_ = -p
install-f: install

uninstall:
	@$(TARGET_VERBOSE)
	-rm -r --interactive=never $(INSTALL.dir)

_RELEASE    = $(shell perl -nle '/^\s*STR_VERSION/ && do { s/.*?"([^"]*)".*/$$1/;print }' $(SRC.pl))

release.show:
	@echo "Release: $(_RELEASE)"

release: $(GEN.tgz)
	@$(TARGET_VERBOSE)
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

# Generating a release file, containing all files with their SID.
# This file should be easily readable by humans and easily parsable by scripts,
# hence following format is used (one per line):
#    SID\tdate\ttime\tfilename\tfull_path
# How it works:
#    "sccs what" returns multiple lines, at least 2, these look like:
#      path/filename:
#          o-saft.pl 1.823 18/11/18 23:42:23
#    this is resorted to have the fixed-width field  SID, date and time  at the
#    beginning (left), followed by the  filename and the full path.
# NOTE: only files available in the repository are used,  therefor the variable
#       $(ALL.src)  is used. Because $(ALL.src) also contains $(ALL.gen), which
#       is wrong here, $(ALL.gen) is  set empty for this target.
#    o-saft.pl is generated from yeast.pl,  but  o-saft.pl  is not a repository
#    file, hence yeast is substituded by o-saft (should occour only once).
$(GEN.rel):   ALL.gen =
$(GEN.rel): $(ALL.src)
	sccs what $(ALL.src) | perl -anle '/^(.*):$$/&&do{$$f=$$m=$$1;$$m=~s#.*/##;next;};/.*?($$m|%[M]%)/&&do{$$f=~s/yeast/o-saft/;$$F[0]=~s/yeast/o-saft/;printf("%s\t%s\t%s\t%s\t%s\n",$$F[1],$$F[2],$$F[3],$$F[0],$$f)};'
rel :$(GEN.rel)

$(_RELEASE).rel: Makefile
	@$(MAKE) -s $(GEN.rel) > $@


.PHONY: all clean install install-f uninstall release.show release rel

variables       = \$$(variables)
#               # define literal string $(variables) for "make doc"
HELP-_project   = ____________________________________ targets for $(Project) _
HELP-help       = print overview of common targets (this one)
HELP-help.all   = print all targets, including test and development targets
#               # defined in t/Makefile.help also
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
HELP-docker.dev = generate local docker image (development version)
HELP-docker.push= install local docker image at Docker repository
HELP-cleantar   = remove '$(GEN.tgz)'
HELP-cleantmp   = remove '$(TMP.dir)'
HELP-clean.all  = remove '$(GEN.tgz) $(ALL.gen)'
HELP-install-f  = install tool in '$(INSTALL.dir)' using '$(GEN.inst)', $(INSTALL.dir) may exist

OPT.single = --s

# alias targets
pl:     $(SRC.pl)
cgi:    $(GEN.cgi.html)
pod:    $(GEN.pod)
html:   $(GEN.html)
text:   $(GEN.text)
wiki:   $(GEN.wiki)
standalone: $(GEN.src)
tar:    $(GEN.tgz)
GREP_EDIT           = 1.54
tar:     GREP_EDIT  = 1.54
tmptar:  GREP_EDIT  = something which hopefully does not exist in the file
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

# docker target uses project's own script to build and remove the image
docker.build:
	@$(TARGET_VERBOSE)
	$(EXE.docker) -OSAFT_VERSION=$(_RELEASE) build
	$(EXE.docker) cp Dockerfile
	$(EXE.docker) cp README
docker: docker.build

docker.rm:
	@$(TARGET_VERBOSE)
	$(EXE.docker) rmi

docker.dev:
	@$(TARGET_VERBOSE)
	docker build --force-rm --rm \
		--build-arg "OSAFT_VM_SRC_OSAFT=https://github.com/OWASP/O-Saft/archive/master.tar.gz" \
		--build-arg "OSAFT_VERSION=$(_RELEASE)" \
		-f Dockerfile -t owasp/o-saft .

# TODO: docker.push  should depend on  docker.build  (above), but  docker.build
#       is not a file and creates a Docker image; means that this target itself
#       has no dependency. Make then executes the target always, which fails if
#       a Docker image already exists.  Need a target, which checks the current
#       Docker image for the proper version.
docker.push:
	@$(TARGET_VERBOSE)
	docker push owasp/o-saft:latest

.PHONY: pl cgi pod html wiki standalone tar tmptar tmptgz cleantar cleantmp help
.PHONY: docker docker.rm docker.dev docker.push

clean.tmp:
	@$(TARGET_VERBOSE)
	rm -rf $(TMP.dir)
clean.tar:
	@$(TARGET_VERBOSE)
	rm -rf $(GEN.tgz)
clean.tgz: clean.tar
clean.docker: docker.rm

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

# Special target to check for edited files;  it only checks the source files of
# the tool (o-saft.pl) but no other source files.
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
# would generate the tarball there also, hence the tarball is specified as full
# path with $(PWD).
# The directory prefix in the tarball is the current directory, aka $(PWD) .
$(GEN.tgz): $(ALL.src)
	@$(TARGET_VERBOSE)
	cd .. && tar zcf $(PWD)/$@ $(ALL.tgz)

$(GEN.tmptgz): $(ALL.src)
	@$(TARGET_VERBOSE)
	tar zcf $@ $^

#_____________________________________________________________________________

HELP-_vv1       = ___________ any target may be used with following suffixes _
HELP--v         = verbose: print target and newer dependencies also
HELP--vv        = verbose: print target and all dependencies also
HELP-_vv2       =  Note: help.*.all-v and help.*.all-vv is not yet supported

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
	@$(EXE.dummy)

%-vv: TARGET_VERBOSE=echo "\# $@: $^"
%-vv: %
	@$(EXE.dummy)

# the traditional way, when target-dependent variables do not work
#%-v:
#	@$(MAKE) $(MFLAGS) $(MAKEOVERRIDES) $* 'TARGET_VERBOSE=# $$@: $$?'
#
#%-vv:
#	@$(MAKE) $(MFLAGS) $(MAKEOVERRIDES) $* 'TARGET_VERBOSE=# $$@: $$^'

#_____________________________________________________________________________
#_____________________________________________ targets for testing and help __|

include $(TEST.dir)/Makefile
    # Note that $(TEST.dir)/Makefile includes all other Makefile.* there

