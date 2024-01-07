#! /usr/bin/make -rRf
#?
#? DESCRIPTION
#?      For more details please see
#?          ../Makefile  Makefile  Makefile.help  Makefile.pod
#?      make help.test.mod
#?
#? VERSION
#?      @(#) Makefile.mod 1.12 24/01/07 13:30:44
#?
#? AUTHOR
#?      22-oct-22 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

HELP-help.test.mod  = targets for testing module functionality

_SID.mod           := 1.12

_MYSELF.mod        := t/Makefile.mod
ALL.includes       += $(_MYSELF.mod)
ALL.inc.type       += mod
ALL.help.tests     += help.test.mod

first-mod-target-is-default: help.test.mod

ifeq (,$(_SID.test))
    -include t/Makefile
endif

help.test.mod:        HELP_TYPE = mod
help.test.mod-v:      HELP_TYPE = mod
help.test.mod-vv:     HELP_TYPE = mod

#_____________________________________________________________________________
#________________________________________________________________ variables __|

TEST.mod.hosts      =

# following names of  LIST.*  variables must match the names of the tool the
# variable should be used for; general rule is:
# for tool named  path/tool.pm  the variable  LIST.path-tool.pm  must be usd
# no targets are generated for empty  LIST.*  variables

LIST.o-saft.pl     :=  
LIST.osaft.pm      :=

# Ciphers.pm supports command/options with or without + and -- prefix
LIST.OSaft-Ciphers.pm-cmd  := \
	aliases constants rfcs  dump    regex   description overview \
	openssl osaft   show    simple  sorted  ssltest     version  \
	get_keys_list   get_names_list

# Ciphers.pm supports command for each of its functions, test with key 0x03001301
LIST.OSaft-Ciphers.pm-get  := \
	get_key     get_sec     get_ssl     get_keyx    get_auth    get_enc \
	get_bits    get_mac     get_rfc     get_name    get_const   get_note \
	get_openssl get_encsize get_iana    get_pfs  \
	get_aliases get_consts  get_names   get_notes

# command/options for Ciphers.pm composed of previous ones and some specials
LIST.OSaft-Ciphers.pm  := \
	$(LIST.OSaft-Ciphers.pm-cmd) \
	$(LIST.OSaft-Ciphers.pm-get:%=%=0x03001301) \
	getter=0x060040   getter=0x02060040 get_key=DES-CBC-MD5 \
	getter=0xC0,0x2C  getter=0x0300C02C get_key=ECDHE-ECDSA-AES256-GCM-SHA384 \
	getter=0xCC,0xA9  getter=0x0300CCA9 get_key=ECDHE-ECDSA-CHACHA20-POLY1305-SHA256 \
	get_key=DHE-PSK-AES128-SHA     get_key=DHE_PSK_WITH_AES_128_CBC_SHA \
	get_key=DHE-PSK-AES128-SHA256  get_key=DHE-PSK-AES128-CBC-SHA256    \
	text2key=0x1301   text2key=0x13,0x01    key2text=0x03001301 \
	is_valid_key=0x1  is_valid_key=03001301 is_valid_key=0x03001301 \
	find_name=ECDHE-ECDSA-CHACHA20-POLY1305-SHA256 \
	find_names=DHE-PSK-AES128 find_keys=DHE-PSK-AES128
    # only $(LIST.OSaft-Ciphers.pm-cmd) is tested here, as they all produce the
    # same output as $(LIST.OSaft-Ciphers--test)

# some command and options supported by Ciphers.pm are supported by $(SRC.pl)
# too, but must be used there as  --test-ciphers-*
# following generated list contains following commands unknown to Ciphers.pm:
#    --test-ciphers-version --test-ciphers-get_keys_list --test-ciphers-get_keys_list
# doesn't harm, they produce nearly emty output
LIST.OSaft-Ciphers--test := $(LIST.OSaft-Ciphers.pm-cmd:%=--test-ciphers-%)

LIST.OSaft-Data.pm     := \
	check_cert  check_conn  check_dest  check_http  check_size \
	checks      data        shorttexts

LIST.o-saft.pl     += $(LIST.OSaft-Ciphers--test)

LIST.OSaft-Doc-Data.pm := \
	--usage version         +VERSION    list  print \
	get     get-markup      get-text    get-as-text \

LIST.Net-SSLinfo.pm-t  := \
	--test-openssl --test-sclient --test-sslmap \
	--test-methods --test-ssleay
LIST.Net-SSLinfo.pm    :=   +VERSION  localhost $(LIST.Net-SSLinfo.pm-t)
LIST.Net-SSLhello.pm   :=   +VERSION  --test-init --test-constant --test-parameter
#LIST.o-saft.pl        += $(LIST.Net-SSLinfo.pm-t)

# tests are functionally the same as testarg-hlp--help-* from Makefile.hlp
LIST.o-saft-man.pm     := \
	FAQ     WHY     CHECK   alias   check   cmd     commands compliance \
	content data    glossar intern  help    hint    legacy   links      \
	opt     options ourstr  pattern range   regex   rfc      text       \
	toc     todo    tools   exit    abbr    warnings \
	cfg-check   cfg-data    cfg-hint    cfg-info    cfg-text cfg-regex  \
	gen-wiki    gen-html    gen-cgi     gen-pod     gen-man \
    # o-saft-man.pm allows any of the above listed arguments like:
    #   o-saft-man.pm toc
    #   o-saft-man.pm --help=toc
    #   o-saft-man.pm --test-toc
    # only the first form is tested here, as they all produce the same output

LIST.OSaft-Trace.pm    := \
	--tests $(LIST.Net-SSLinfo.pm-t)  --test-memory --test-regex \
	--test-avail --test-init --test-maps --test-prot --test-vars
# OSaft/Trace.pm doesn't handle the options, hence call o-saft.pl with them

LIST.o-saft.pl         += $(LIST.OSaft-Trace.pm)

# command and checks NOT YET IMPLEMENTED are hardcoded here,
# should be the same commands_notyet in osaft.pm
LIST.o-saft.notyet     := \
	+closure    +cipher_order   +cipher_weak    +cps_valid  +fallback \
	+open_pgp   +lzo    +sgc    +scsv   +time   +zlib   \

HELP-_mod1          = _____________________________ testing module functionality _
HELP-test.mod       = test various module functionalities
HELP-test.mod.log   = same as test.mod but store output in '$(TEST.logdir)/'

#_____________________________________________________________________________
#______________________________________________________ targets for testing __|

# programs to be tested here are in $(SRC.pm)
ifndef SRC.pm
    # define dummy to inform user about missing macro
    SRC.pm          = __SRC.pm_
    LIST.__SRC.pm_  = not-defined-in-Makefile.mod
endif

# all targets are generated, see Makefile.gen

ifndef mod-macros-generated
    $(foreach _prg, $(SRC.pm),\
        $(call GEN.targets-init,testarg,mod,$(_prg),LIST.$(subst /,-,$(_prg))) \
    )
    undefine _prg
endif

# some special adaptions to generated targets

# OSaft/Doc/Data.pm function needs a file where to read the information
# it's found automatically when using o-saft.pl but not with OSaft/Doc/Data.pm
testarg-mod-OSaft-Doc-Data.pm_%: TEST.args  = help.txt

# OSaft/Trace.pm does not make sense without a calling parent
testarg-mod-OSaft-Trace.pm_%:   EXE.pl      = ../$(SRC.pl)

# more info with pretty printed output: --header
testarg-mod-o-saft-man.pm_%:    TEST.args   = --header

#_____________________________________________________________________________
#_____________________________________________________________________ test __|

#ALL.test.mod  # defined in GEN.targets-init
ALL.test.mod.log    = $(ALL.test.mod:%=%.log)

test.mod.log-compare:   TEST.target_prefix  = testarg-mod-
test.mod.log-move:      TEST.target_prefix  = testarg-mod-
test.mod.log:           TEST.target_prefix  = testarg-mod-

test.mod:           $(ALL.test.mod)
test.mod.all:       $(ALL.test.mod)
test.mod.log:       $(ALL.test.mod.log) test.log-compare-hint
