#! /usr/bin/make -rRf
#?
#? NAME
#?      Makefile        - makefile for O-Saft project
#?
#? SYNOPSYS
#?      make [options] [target] [...]
#?
#? DESCRIPTION
#?      For help about the targets herein, please see:
#?
#?          make
#?          make help
#?
#?      For detailled documentation how GNU Make, its syntax and conventions as
#?      well as some special syntax of macros and targets is used here,  please
#?      refer to  Makefile.pod , for example by using  "perldoc Makefile.pod" .
#?      The term  "SEE Make:some text"  is used to reference to Makefile.pod .
#
# HACKER's INFO
#       For the public available targets see below of  "well known targets" .
#?
#? VERSION
#?      @(#) Makefile 2.23 23/04/16 23:50:05
#?
#? AUTHOR
#?      21-dec-12 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

_SID            = 2.23
                # define our own SID as variable, if needed ...
                # SEE O-Saft:Makefile Version String
                # Known variables herein (8/2019) to be changed are:
                #     _SID
                #     _INST.text
                #     _INST.is_edit

ALL.includes   := Makefile
                # must be  :=  to avoid overwrite after includes
                # each $(TEST.dir)/Makefile* will add itself to ALL.includes

MAKEFILE        = Makefile
                # define variable for myself,  this allows to use  some targets
                # within other makefiles
                # Note that  $(MAKEFILE) is used where any Makefile is possible
                # and  Makefile  is used when exactly this file is meant.
                # $(ALL.Makefiles) is used, when all Makefiles are needed.

MAKEFLAGS       = --no-builtin-variables --no-builtin-rules
.SUFFIXES:

.DEFAULT:
	@echo "**ERROR: unknown target '$(MAKECMDGOALS)'"

first-target-is-default: help

#_____________________________________________________________________________
#________________________________________________________________ variables __|

O-Project       = o-saft
O-ProjectName   = O-Saft
O-INSTALL.dir   = /usr/local/$(O-Project)

# tool source files
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
OSAFT.pm        = Ciphers.pm Data.pm Text.pm error_handler.pm
USR.pm          = \
		  $(O-Project)-dbx.pm \
		  $(O-Project)-man.pm \
		  $(O-Project)-usr.pm
SRC.pm          = \
		  osaft.pm \
		  $(NET.pm:%=Net/%)   \
		  $(OSAFT.pm:%=OSaft/%) \
		  $(USR.pm) \
		  $(OSD.pm)
SRC.sh          = $(O-Project)
SRC.pl          = $(O-Project).pl
SRC.tcl         = $(O-Project).tcl
SRC.gui         = $(O-Project).tcl $(O-Project)-img.tcl
SRC.cgi         = $(O-Project).cgi
SRC.php         = $(O-Project).php
SRC.docker      = \
		  $(O-Project)-docker \
		  $(O-Project)-docker-dev \
		  Dockerfile
SRC.rc          = .$(SRC.pl)

SRC.exe         = $(SRC.pl) $(SRC.gui) $(CHK.pl) $(DEV.pl) $(SRC.sh)

SRC.make        = Makefile
SRC.misc        = README.md CHANGES
SRC.inst        = $(SRC.contrib.dir)/INSTALL-template.sh

# contrib files
SRC.contrib.dir     = contrib
SRC.contrib.examples= filter_examples usage_examples
SRC.contrib.post.awk= \
		  Cert-beautify.awk \
		  HTML-simple.awk   HTML-table.awk \
		  JSON-struct.awk   JSON-array.awk \
		  XML-attribute.awk XML-value.awk \
		  lazy_checks.awk
SRC.contrib.post    = \
		  Cert-beautify.pl \
		  alertscript.pl \
		  alertscript.cfg \
		  bunt.pl \
		  bunt.sh \
		  symbol.pl
SRC.contrib.misc    = \
		  cipher_check.sh \
		  critic.sh \
		  gen_standalone.sh \
		  distribution_install.sh \
		  install_openssl.sh \
		  install_perl_modules.pl \
		  INSTALL-template.sh \
		  Dockerfile.alpine-3.6

SRC.contrib.zap     = zap_config.sh zap_config.xml
# some file should get the $(O-Project) suffix, which is appended later
SRC.contrib.complete= \
		  bash_completion \
		  dash_completion \
		  fish_completion \
		  tcsh_completion
SRC.contrib     = \
		  $(SRC.contrib.complete:%=$(SRC.contrib.dir)/%_$(O-Project)) \
		  $(SRC.contrib.examples:%=$(SRC.contrib.dir)/%) \
		  $(SRC.contrib.post.awk:%=$(SRC.contrib.dir)/%) \
		  $(SRC.contrib.post:%=$(SRC.contrib.dir)/%) \
		  $(SRC.contrib.misc:%=$(SRC.contrib.dir)/%) \
		  $(SRC.contrib.zap:%=$(SRC.contrib.dir)/%)


TEST.dir        = t
TEST.logdir     = $(TEST.dir)/log
TEST.do         = SSLinfo.pl \
                  o-saft_bench.sh \
                  cloc-total.awk \
                  critic_345.sh \
                  test-bunt.pl.txt
TEST.critic.rc  = .perlcriticrc
SRC.test        = \
                  $(TEST.do:%=$(TEST.dir)/%) \
                  $(TEST.critic.rc:%=$(TEST.dir)/%)
TEST.Makefiles   = \
		  Makefile         Makefile.inc   Makefile.help  Makefile.pod \
		  Makefile.gen \
		  Makefile.opt     Makefile.cmd   Makefile.ext   Makefile.exit \
		  Makefile.cgi     Makefile.tcl   Makefile.misc  Makefile.warnings \
		  Makefile.critic  Makefile.dev   Makefile.etc   Makefile.template \
		  Makefile.docker  Makefile.FQDN  Makefile.examples
SRC.Makefiles   = $(TEST.Makefiles:%=$(TEST.dir)/%)

# documentation files
DOC.dir         = docs
DOC.src         = o-saft_CLI_data_flow.odg \
		  o-saft_GUI_data_flow.odg \
		  o-saft_docker.de.odg \
		  o-saft_docker.en.odg
SRC.doc         = $(DOC.src:%=$(DOC.dir)/%)
WEB.dir         = docs/img
WEB.src         = \
		  img.css \
		  O-Saft_CLI-cipher.png \
		  O-Saft_CLI-altname.png \
		  O-Saft_GUI-altname.png \
		  O-Saft_GUI-check.png \
		  O-Saft_GUI-cmd--docker.png \
		  O-Saft_GUI-cmd.png \
		  O-Saft_GUI-cmd-0.png \
		  O-Saft_GUI-filter.png \
		  O-Saft_GUI-help-0.png \
		  O-Saft_GUI-help-1.png \
		  O-Saft_GUI-opt.png \
		  O-Saft_GUI-prot.png \
		  O-Saft_GUI-vulns.png \
		  O-Saft_CLI-vulns.png \
		  O-Saft_CLI__faked.txt
SRC.web         = $(WEB.src:%=$(WEB.dir)/%)

# generated files
O-TMP.dir         = /tmp/$(O-Project)
GEN.html        = $(DOC.dir)/$(O-Project).html
GEN.cgi.html    = $(DOC.dir)/$(O-Project).cgi.html
GEN.text        = $(DOC.dir)/$(O-Project).txt
GEN.wiki        = $(DOC.dir)/$(O-Project).wiki
GEN.man         = $(DOC.dir)/$(O-Project).1
GEN.pod         = $(DOC.dir)/$(O-Project).pod
GEN.src         = $(SRC.contrib.dir)/$(O-Project)-standalone.pl
GEN.pdf         = $(SRC.doc:%.odg=%.pdf)
GEN.inst        = INSTALL.sh
GEN.tags        = tags
GEN.rel         = $(O-Project).rel

GEN.tgz         = $(O-Project).tgz
GEN.tmptgz      = $(O-TMP.dir)/$(GEN.tgz)

# generated files for internal use, i.e. $(SRC.tcl)
# TODO: because make does not allow = in target names, the generated targets
#       should use - instead
LIST.DOC_data   = --help --help=opts --help=commands --help=glossar --help=alias \
		  --help=data --help=data --help=checks --help=regex --help=rfc \
		  --help=ciphers-html --help=ciphers-text
# --help=warnings  uses a different command to be generated
GEN.DOC.data    = $(LIST.DOC_data:%=$(DOC.dir)/$(SRC.pl).%)
GEN.DOC.data   += $(DOC.dir)/$(SRC.pl).--help=warnings

# summary variables
GEN.docs        = $(GEN.pod) $(GEN.html) $(GEN.cgi.html) $(GEN.text) $(GEN.wiki) $(GEN.man)
# NOTE: sequence in ALL.Makefiles is important, for example when used in target doc
ALL.Makefiles   = $(SRC.make) $(SRC.Makefiles)
ALL.osaft       = $(SRC.pl)  $(SRC.gui) $(CHK.pl)  $(SRC.pm)  $(SRC.sh) $(SRC.txt) $(SRC.rc) $(SRC.docker)
ALL.exe         = $(SRC.exe) $(SRC.cgi) $(SRC.php) $(GEN.src) $(SRC.docker)
ALL.tst         = $(SRC.test)
ALL.contrib     = $(SRC.contrib)
ALL.doc         = $(SRC.doc) $(SRC.web)
ALL.pm          = $(SRC.pm)
ALL.gen         = $(GEN.src) $(GEN.docs) $(GEN.DOC.data)
ALL.docs        = $(SRC.doc) $(GEN.docs)
    # NOTE: ALL.docs are the files for user documentation, ALL.doc are SRC-files
    #       $(GEN.wiki) is rarley used but part of ALL.gen for simplicity
#               # $(GEN.tags) added in t/Makefile.misc
ALL.src         = \
		  $(ALL.exe) \
		  $(ALL.pm) \
		  $(SRC.txt) \
		  $(SRC.rc) \
		  $(SRC.misc) \
		  $(SRC.doc) \
		  $(ALL.gen) \
		  $(ALL.Makefiles) \
		  $(ALL.tst) \
		  $(ALL.contrib)
ALL.tgz         = $(ALL.src:%=O-Saft/%)
ALL.tgz        += O-Saft/$(GEN.inst)

# internal used make
MAKE            = $(MAKE_COMMAND)
# some rules need to have a command, otherwise they are not evaluated
EXE.dummy       = /bin/echo -n ""
# internal used tools (paths hardcoded!)
EXE.single      = contrib/gen_standalone.sh
EXE.docker      = o-saft-docker
EXE.pl          = $(SRC.pl)
#                   SRC.pl is used for generating a couple of data

# other tools
EXE.office      = libreoffice

# summary variables (mainly used for INSTALL.sh)
_ALL.devtools.intern  += $(EXE.single)
_ALL.devtools.extern  += sccs gpg sha256sum docker
ALL.tools.optional     = aha perldoc pod2html pod2man pod2pdf pod2text pod2usage podman podviewer tkpod stty tput
ALL.perlmodules = Net::DNS Net::SSLeay IO::Socket::INET IO::Socket::SSL Time::Local
ALL.devtools    = $(_ALL.devtools.intern)   $(_ALL.devtools.extern)
ALL.devmodules  = $(_ALL.devmodules.intern) $(_ALL.devmodules.extern)
#                 defined in t/Makefile.misc
ALL.osaftmodules= osaft $(NET.pm:%.pm=Net::%) $(OSAFT.pm:%.pm=OSaft::%) OSaft::Doc::Data

# following for documentation, not yet used (2022)
#_ALL.tools.dbian.pkg  = aha libtk-pod-perl perl-doc perl-doc-html pod2pdf

# INSTALL.sh must not contain duplicate files, hence the variable's content
# is sorted using make's built-in sort which removes duplicates
_INST.osaft_cgi = $(sort $(SRC.cgi) $(SRC.php) $(GEN.cgi.html))
_INST.osaft_doc = $(sort $(GEN.pod) $(GEN.man) $(GEN.html))
_INST.contrib   = $(sort $(ALL.contrib))
_INST.osaft     = $(sort $(ALL.osaft))
_INST.devtools  = $(sort $(ALL.devtools))
_INST.tools_int = $(sort $(_ALL.devtools.intern))
_INST.tools_ext = $(sort $(_ALL.devtools.extern))
_INST.tools_opt = $(sort $(ALL.tools.optional))
_INST.tools_other = $(sort $(ALL.tools.ssl))
_INST.devmodules= $(sort $(ALL.devmodules))
_INST.genbytext = generated data by Makefile 2.23 from $(SRC.inst)
_INST.gen_text  = generated data from Makefile 2.23
EXE.install = sed -e 's@INSERTED_BY_MAKE_INSTALLDIR@$(O-INSTALL.dir)@'         \
		  -e 's@INSERTED_BY_MAKE_CONTRIBDIR@$(SRC.contrib.dir)@'     \
		  -e 's@INSERTED_BY_MAKE_CONTRIB@$(_INST.contrib)@'          \
		  -e 's@INSERTED_BY_MAKE_TOOLS_OTHER@$(_INST.tools_other)@'  \
		  -e 's@INSERTED_BY_MAKE_TOOLS_OPT@$(_INST.tools_opt)@'      \
		  -e 's@INSERTED_BY_MAKE_DEVTOOLSINT@$(_INST.tools_int)@'    \
		  -e 's@INSERTED_BY_MAKE_DEVTOOLSEXT@$(_INST.tools_ext)@'    \
		  -e 's@INSERTED_BY_MAKE_DEVMODULES@$(_INST.devmodules)@'    \
		  -e 's@INSERTED_BY_MAKE_PERL_MODULES@$(ALL.perlmodules)@'   \
		  -e 's@INSERTED_BY_MAKE_OSAFT_SH@$(SRC.sh)@'                \
		  -e 's@INSERTED_BY_MAKE_OSAFT_PL@$(SRC.pl)@'                \
		  -e 's@INSERTED_BY_MAKE_OSAFT_GUI@$(SRC.tcl)@'              \
		  -e 's@INSERTED_BY_MAKE_OSAFT_CGI@$(_INST.osaft_cgi)@'      \
		  -e 's@INSERTED_BY_MAKE_OSAFT_STAND@$(GEN.src)@'            \
		  -e 's@INSERTED_BY_MAKE_OSAFT_DOCKER@$(EXE.docker)@'        \
		  -e 's@INSERTED_BY_MAKE_OSAFT_DOC@$(_INST.osaft_doc)@'      \
		  -e 's@INSERTED_BY_MAKE_OSAFT_MODULES@$(ALL.osaftmodules)@' \
		  -e 's@INSERTED_BY_MAKE_OSAFT@$(_INST.osaft)@'              \
		  -e 's@INSERTED_BY_MAKE_FROM@$(_INST.genbytext)@'           \
		  -e 's@INSERTED_BY_MAKE@$(_INST.gen_text)@'
                # note that the sequence of the -e commands is important
                # last substitude is fallback to ensure everything is changed

# generate f- targets to print HELP text for each target
_HELP.my_targets= $(shell $(EXE.eval) $(MAKEFILE))
_HELP.alltargets= $(shell $(EXE.eval) $(ALL.includes))
_HELP.help      = $(ALL.help:%=f-%)
                # quick&dirty because each target calls make (see below)

#_____________________________________________________________________________
#___________________________________________________________ default target __|

# define header part of default target
help:           HELP_HEAD = $(HELP_RULE)
help.all:       HELP_HEAD = $(HELP_RULE)
help.log:       HELP_HEAD = $(HELP_RULE)
help.all.log:   HELP_HEAD = $(HELP_RULE)
doc:            HELP_HEAD = $(HELP_RULE)
doc.all:        HELP_HEAD = $(HELP_RULE)

# define body part of default target
# TODO: adapt _help_* macros and targets according own naming convention
_help_also_               = _help_also
_help_body_               = _help_body_me
_help_list_               =
help.all:     _help_body_ = _help_body_all
help.all:     _help_list_ = _help_list
doc:          _help_body_ = _eval_body_me
doc.all:      _help_body_ = _eval_body_all
doc:          _help_also_ =
doc.all:      _help_also_ =
doc.all:      _help_list_ = _help_list

# for targets defined in Makefile.help
help.all%:    _help_body_ = _help_body_all
help.all%:    _help_list_ = _help_list
%.all-v:     _help_text-v =
_help_text-v              = \# to see Makefile, where targets are defined, use: $(MAKE_COMMAND) $(MAKECMDGOALS)-v

#_____________________________________________________________________________
#_________________________________________________________ internal targets __|

# SEE Make:.SECONDEXPANSION
.SECONDEXPANSION:

# If variables, like  $(_HELP.*targets),  contain duplicate target names (which
# is intended), only one will be executed by  $(MAKE),  hence the 2nd occurance
# is missing.
_eval_body_me:
	@$(MAKE) -s $(_HELP.my_targets)
	@echo "$(HELP_LINE)"

_eval_body_all:
	@$(MAKE) -s $(_HELP.alltargets)

_help_body_me:
	@$(EXE.help) $(MAKEFILE)
	@echo "$(HELP_LINE)"

_help_body_all:
	@$(EXE.help) $(ALL.includes)

_help_list:
	@echo ""
	@echo "		#___________ targets for information about test targets... _"
	@$(MAKE) $(_HELP.help)
	@echo "$(HELP_LINE)"
	@echo "$(_help_text-v)"

_help_also:
	@echo "# to expand variables, use: $(MAKE_COMMAND) doc"

# ensure that target help: from this file is used and not help%
help help.all doc doc.all: _help.HEAD $$(_help_body_) $$(_help_list_) $$(_help_also_)
	@$(TRACE.target)

help.all-v help.all-vv: help.all
	@$(EXE.dummy)
#doc.all-v doc.all-vv: help.all     # TODO: not implemented yet

.PHONY: help help.all doc doc.all

#_____________________________________________________________________________
#__________________________________________________________________ targets __|

HELP-_known     = _______________________________________ well known targets _
HELP-all        = does nothing; alias for help
HELP-clean      = remove all generated files '$(ALL.gen) $(GEN.tags)'
HELP-release    = generate signed '$(GEN.tgz)' from sources
HELP-install    = install tool in '$(O-INSTALL.dir)' using '$(GEN.inst)', $(O-INSTALL.dir) must exist
HELP-uninstall  = remove installtion directory '$(O-INSTALL.dir)' completely

$(O-INSTALL.dir):
	@$(TRACE.target)
	mkdir $(_INSTALL_FORCE_) $(O-INSTALL.dir)

all:    help

clean:  clean.tmp clean.tar clean.gen
clear:  clean

# target calls installed $(SRC.pl) to test general functionality
install: $(GEN.inst) $(O-INSTALL.dir)
	@$(TRACE.target)
	$(GEN.inst) $(O-INSTALL.dir) \
	    && $(O-INSTALL.dir)/$(SRC.pl) --no-warning --tracearg +quit > /dev/null
install-f: _INSTALL_FORCE_ = -p
install-f: install

uninstall:
	@$(TRACE.target)
	-rm -r --interactive=never $(O-INSTALL.dir)

_RELEASE    = $(shell perl -nle '/^\s*sub _VERSION/ && do { s/.*?"([^"]*)".*/$$1/;print }' $(SRC.pl))

release.show:
	@echo "Release: $(_RELEASE)"

release: $(GEN.tgz)
	@$(TRACE.target)
	mkdir -p $(_RELEASE)
	sha256sum $(GEN.tgz) > $(_RELEASE)/$(GEN.tgz).sha256
	@cat $(_RELEASE)/$(GEN.tgz).sha256
	gpg --local-user o-saft -a --detach-sign $(GEN.tgz)
	gpg --verify $(GEN.tgz).asc $(GEN.tgz)
	mv $(GEN.tgz).asc $(_RELEASE)/
	mv $(GEN.tgz)     $(_RELEASE)/
	@echo "# don't forget:"
	@echo "#   # change digest: sha256:... in README.md; upload to github"
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
# what may also return lines like:
#          @(#) filename 1.245 19/11/19 12:23:42',
#          @(#) filename generated by 1.227 19/11/19 10:12:13
# The perl script takes care of them  and ignores or pretty prints the strings. 
# The "generated by" may occour i.e. in o-saft.tcl.
# NOTE: only files available in the repository are used, therefore the variable
#       $(ALL.src)  is used. Because $(ALL.src) also contains $(ALL.gen), which
#       is wrong here, $(ALL.gen) is  set empty for this target.
#    o-saft.pl is generated from yeast.pl,  but  o-saft.pl  is not a repository
#    file, hence yeast is substituded by o-saft (should occour only once).
$(GEN.rel):   ALL.gen =
$(GEN.rel): $(ALL.src)
	@sccs what $(ALL.src) | \
	perl -anle '/ generated by /&&next;/^(.*):$$/&&do{$$f=$$m=$$1;$$m=~s#.*/##;next;};/.*?($$m|%[M]%)/&&do{$$f=~s/yeast/o-saft/;$$F[0]=~s/yeast/o-saft/;$$t=$$F[3];$$q=chr(0x27);$$t=~s#["$$q,]##g;printf("%s\t%s\t%s\t%s\t%s\n",$$F[1],$$F[2],$$t,$$F[0],$$f)};'
rel :$(GEN.rel)

$(_RELEASE).rel: Makefile
	@$(MAKE) -s $(GEN.rel) > $@


.PHONY: all clean install install-f uninstall release.show release rel

variables       = \$$(variables)
#               # define literal string $(variables) for "make doc"
HELP-_project   = ____________________________________ targets for $(O-Project) _
HELP-help       = print common targets for O-Saft (this help)
HELP-doc        = same as help, but evaluates '$(variables)'
HELP-pl         = generate '$(SRC.pl)' from managed source files
HELP-cgi        = generate HTML page for use with CGI '$(GEN.cgi.html)'
HELP-man        = generate MAN format help '$(GEN.man)'
HELP-pod        = generate POD format help '$(GEN.pod)'
HELP-html       = generate HTML format help '$(GEN.html)'
HELP-text       = generate plain text  help '$(GEN.text)'
HELP-wiki       = generate mediawiki format help '$(GEN.wiki)'
HELP-docs       = generate '$(GEN.docs)'; see also target doc.data
HELP-tar        = generate '$(GEN.tgz)' from all source prefixed with O-Saft/
HELP-tmptar     = generate '$(GEN.tmptgz)' from all sources without prefix
HELP-doc.data   = generate '$(GEN.DOC.data)' for $(SRC.tcl)
HELP-gen.all    = generate most "generatable" file
HELP-docker     = generate local docker image (release version) and add updated files
HELP-docker.dev = generate local docker image (development version)
HELP-docker.push= install local docker image at Docker repository
HELP-clean.tmp  = remove '$(O-TMP.dir)'
HELP-clean.tar  = remove '$(GEN.tgz)'
HELP-clean.gen  = remove '$(ALL.gen)' '$(GEN.inst)' '$(GEN.tags)'
HELP-clean.all  = remove '$(ALL.gen)' '$(GEN.inst)' '$(GEN.tags)' '$(GEN.tgz)'
HELP-install-f  = install tool in '$(O-INSTALL.dir)' using '$(GEN.inst)', '$(O-INSTALL.dir)' may exist
HELP-o-saft.rel = generate '$(GEN.rel)'
#               # HELP-o-saft.rel hardcoded, grrr


HELP-_vv1       = ___________ any target may be used with following suffixes _
HELP--v         = verbose: print target and newer dependencies also
HELP--vv        = verbose: print target and all dependencies also

HELP-_project2  = __________________ targets to get more help and information _
HELP-help.all   = print all targets, including most test and development targets
#               # defined in t/Makefile.help also
HELP-help.help  = print targets to get information/documentation from Makefiles

# alias targets
pl:         $(SRC.pl)
cgi:        $(GEN.cgi.html)
man:        $(GEN.man)
pdf:        $(GEN.pdf)
pod:        $(GEN.pod)
html:       $(GEN.html)
text:       $(GEN.text)
wiki:       $(GEN.wiki)
docs:       $(GEN.docs)
standalone: $(GEN.src)
tar:        $(GEN.tgz)
_INST.is_edit           = 2.23
tar:     _INST.is_edit  = 2.23
tmptar:  _INST.is_edit  = something which hopefully does not exist in the file
tmptar:     $(GEN.tmptgz)
tmptgz:     $(GEN.tmptgz)
cleangen:   clean.gen
cleantar:   clean.tar
cleantgz:   clean.tar
cleantmp:   clean.tmp
cleartar:   clean.tar
cleartgz:   clean.tar
cleartmp:   clean.tmp
clear.all:  clean.tar clean
clean.all:  clean.tar clean
tgz:        tar
gen.all:    $(ALL.gen)
doc.data:   $(GEN.DOC.data)
docdata:    $(GEN.DOC.data)
tcl.data:
	@echo "**ERROR: ancient target; please use 'doc.data'"
tcldata:    tcl.data

# docker target uses project's own script to build and remove the image
docker.build:
	@$(TRACE.target)
	$(EXE.docker) -OSAFT_VERSION=$(_RELEASE) build
	$(EXE.docker) cp Dockerfile
	$(EXE.docker) cp README.md
docker: docker.build

docker.rm:
	@$(TRACE.target)
	$(EXE.docker) rmi

docker.dev:
	@$(TRACE.target)
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
	@$(TRACE.target)
	docker push owasp/o-saft:latest

.PHONY: pl cgi man pod html wiki standalone tar tmptar tmptgz cleantar cleantmp help
.PHONY: docker docker.rm docker.dev docker.push

clean.gen:
	@$(TRACE.target)
	rm -rf $(ALL.gen) $(GEN.inst)
clean.tmp:
	@$(TRACE.target)
	rm -rf $(O-TMP.dir)
clean.tar:
	@$(TRACE.target)
	rm -rf $(GEN.tgz)
clean.tgz: clean.tar
clean.docker: docker.rm

# avoid matching implicit rule help% in some of following targets
$(OSD.dir)/help.txt: 
	@$(TRACE.target)

#_____________________________________________________________________________
#_______________________________________________ targets for generated files__|

# targets for generation
$(O-TMP.dir)/Net $(O-TMP.dir)/OSaft $(O-TMP.dir)/OSaft/Doc $(O-TMP.dir)/$(SRC.contrib.dir) $(O-TMP.dir)/$(TEST.dir):
	@$(TRACE.target)
	mkdir -p $@

# cp fails if SRC.pl is read-only, hence we remove it; it is generated anyway
$(SRC.pl): $(DEV.pl)
	@$(TRACE.target)
	rm -f $@
	cp $< $@

# generation fails if GEN.src is read-only, hence we remove it; it is generated anyway
$(GEN.src):  $(EXE.single) $(SRC.pl) $(ALL.pm)
	@$(TRACE.target)
	@rm -rf $@
	$(EXE.single) --s                              > $@
	@chmod 555 $@

$(GEN.man):  $(SRC.pl) $(OSD.pm) $(USR.pm) $(SRC.txt) $(GEN.pod)
	@$(TRACE.target)
	$(SRC.pl) --no-rc --no-warning --help=gen-man  > $@

$(GEN.pod):  $(SRC.pl) $(OSD.pm) $(USR.pm) $(SRC.txt)
	@$(TRACE.target)
	$(SRC.pl) --no-rc --no-warning --help=gen-pod  > $@

$(GEN.text): $(SRC.pl) $(OSD.pm) $(USR.pm) $(SRC.txt)
	@$(TRACE.target)
	$(SRC.pl) --no-rc --no-warning --help          > $@

$(GEN.wiki): $(SRC.pl) $(OSD.pm) $(USR.pm) $(SRC.txt)
	@$(TRACE.target)
	$(SRC.pl) --no-rc --no-warning --help=gen-wiki > $@

$(GEN.html): $(SRC.pl) $(OSD.pm) $(USR.pm) $(SRC.txt)
	@$(TRACE.target)
	$(SRC.pl) --no-rc --no-warning --help=gen-html > $@

$(GEN.cgi.html): $(SRC.pl) $(OSD.pm) $(USR.pm) $(SRC.txt)
	@$(TRACE.target)
	$(SRC.pl) --no-rc --no-warning --help=gen-cgi  > $@

$(GEN.inst): $(SRC.inst) Makefile
	@$(TRACE.target)
	$(EXE.install) $(SRC.inst) > $@
	chmod +x $@

$(GEN.tgz)--to-noisy: $(ALL.src)
	@$(TRACE.target)
	@grep -q '$(_INST.is_edit)' $? \
	    && echo "file(s) being edited or with invalid SID" \
	    || echo tar zcf $@ $^

# generating file containing our messages uses target from t/Makefile.warnings
# hence make is called recursively for this special file
# TODO: this is a dirty hack, because no Makefiles from t/ should be used here
# most files could also be generated with: $(SRC.pl) --gen-docs
# SEE GNU Make:Pattern Rule
$(DOC.dir)/$(SRC.pl).%warnings: $(SRC.pl)
	@$(TRACE.target)
	$(MAKE_COMMAND) -s warnings-info > $@

$(DOC.dir)/$(SRC.pl).%: $(SRC.pl)
	@$(TRACE.target)
	$(SRC.pl) --no-rc $* > $@

# use libreoffice to generate PDF from .odg
# unfortunately  libreoffice has no option to specify the name of the output,
# hence we need to use its --outdir option instead of make's $@
# ancient libreoffice (before 5.0) may also need following option:
#     -env:UserInstallation=file:///tmp/dummy${USER}
# FIXME: (11/2021) libreoffice --headless  generates a file slighly different
#        compared to the file generated interactively (reason yet unknown)
#        we keep the generation here, to avoid missing files
$(DOC.dir)/%.pdf: $(DOC.dir)/%.odg
	@$(TRACE.target)
	$(EXE.office) --headless --nologo --nolockcheck --norestore --convert-to pdf:draw_pdf_Export --outdir $(DOC.dir)/ $^ 

# Special target to check for edited files;  it only checks the source files of
# the tool (o-saft.pl) but no other source files.
_notedit: $(SRC.exe) $(SRC.pm) $(SRC.rc) $(SRC.txt)
	@$(TRACE.target)
	@grep -q '$(_INST.is_edit)' $? \
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
$(GEN.tgz): $(ALL.src) $(GEN.tags) $(GEN.inst)
	@$(TRACE.target)
	cd .. && tar zcf $(PWD)/$@ $(ALL.tgz)

$(GEN.tmptgz): $(ALL.src) $(GEN.tags)
	@$(TRACE.target)
	tar zcf $@ $^

#_____________________________________________________________________________
#__________________________________________________________ verbose targets __|

# verbose/trace command
#       TRACE.target    is the command to be used to print the target's name
#                       it is epmty by default
#       TRACE.target    can be set as environment variable, or used on command
#                       line when calling make
#                       it is also used internal for the -v targets, see below
# examples:
#  TRACE.target = echo "\# --Target: $@--"
#  TRACE.target = echo "\# --Target: $@: newer dependencies: $? --"
#  TRACE.target = echo "\# --Target: $@: all dependencies: $^ --"

# verbose targets
# NOTE: need at least one command for target execution
%-v: TRACE.target   = echo "\# $@: $?"
%-v: %
	@$(EXE.dummy)

%-vv: TRACE.target  = echo "\# $@: $^"
%-vv: %
	@$(EXE.dummy)

# the traditional way, when target-dependent variables do not work
#%-v:
#	@$(MAKE) $(MFLAGS) $(MAKEOVERRIDES) $* 'TRACE.target=echo \# $$@: $$?'
#
#%-vv:
#	@$(MAKE) $(MFLAGS) $(MAKEOVERRIDES) $* 'TRACE.target=echo \# $$@: $$^'

#_____________________________________________________________________________
#_____________________________________________ targets for testing and help __|

include $(TEST.dir)/Makefile
    # Note that $(TEST.dir)/Makefile includes all other Makefile.* there

