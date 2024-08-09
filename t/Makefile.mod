#! /usr/bin/make -rRf
#?
#? DESCRIPTION
#?      For more details please see
#?          ../Makefile  Makefile  Makefile.help  Makefile.pod
#?      make help.test.mod
#?
#? VERSION
#?      @(#) Makefile.mod 3.17 24/08/09 21:49:04
#?
#? AUTHOR
#?      22-oct-22 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

HELP-help.test.mod  = targets for testing module functionality

O-SID.mod          := 3.17
O-SELF.mod         := t/Makefile.mod
ALL.includes       += $(O-SELF.mod)
ALL.inc.type       += mod
ALL.help.tests     += help.test.mod

first-mod-target-is-default: help.test.mod

ifeq (,$(O-SID.test))
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

# Ciphers.pm supports command/options with or without + and -- prefix
LIST.lib-Ciphers.pm-cmd  := \
	aliases constants rfcs  dump    regex   description overview \
	openssl osaft   show    simple  sorted  ssltest     version  \
	get_keys_list   get_names_list

# Ciphers.pm supports command for each of its functions, test with key 0x03001301
LIST.lib-Ciphers.pm-get := \
	get_key     get_sec     get_ssl     get_keyx    get_auth    get_enc \
	get_bits    get_mac     get_rfc     get_name    get_const   get_note \
	get_openssl get_encsize get_iana    get_pfs  \
	get_aliases get_consts  get_names   get_notes

# command/options for Ciphers.pm composed of previous ones and some specials
LIST.lib-Ciphers.pm    := \
	$(LIST.lib-Ciphers.pm-cmd) \
	$(LIST.lib-Ciphers.pm-get:%=%=0x03001301) \
	getter=0x060040   getter=0x02060040 get_key=DES-CBC-MD5 \
	getter=0xC0,0x2C  getter=0x0300C02C get_key=ECDHE-ECDSA-AES256-GCM-SHA384 \
	getter=0xCC,0xA9  getter=0x0300CCA9 get_key=ECDHE-ECDSA-CHACHA20-POLY1305-SHA256 \
	get_key=DHE-PSK-AES128-SHA     get_key=DHE_PSK_WITH_AES_128_CBC_SHA \
	get_key=DHE-PSK-AES128-SHA256  get_key=DHE-PSK-AES128-CBC-SHA256    \
	get_pfs=0x0bad0bad   get_iana=0x0bad0bad \
	get_iana=0x03001301  get_iana=03001301  get_iana=0x13,01 get_iana=13,01 \
	get_const=0x03001301 \
	text2key=0x1301   text2key=0x13,0x01    key2text=0x03001301 \
	find_consts=AES_128_GCM_SHA256 \
	is_valid_key=0x1  is_valid_key=03001301 is_valid_key=0x03001301 \
	is_rc4=invalid \
	is_adh=0x03000018 is_adh=ADH-RC4-MD5    is_adh=DHanon-RC4-MD5 \
	is_adh=ADH_RC4_128_MD5        is_adh=DH_anon_WITH_RC4_MD5 \
	is_adh=DH_anon_WITH_RC4_128_MD5 \
	is_cbc=0x03000012 is_cbc=EDH-DSS-CBC-SHA is_cbc=EDH-DSS-DES-CBC-SHA \
	is_cbc=EDH_DSS_DES_64_CBC_SHA is_cbc=DHE_DSS_WITH_DES_CBC_SHA \
	is_des=0x03000012 is_des=EDH-DSS-CBC-SHA is_des=EDH-DSS-DES-CBC-SHA \
	is_des=EDH_DSS_DES_64_CBC_SHA is_des=DHE_DSS_WITH_DES_CBC_SHA \
	is_edh=0x03000032 is_edh=DHE-DSS-AES128-SHA is_edh=EDH-DSS-AES128-SHA \
	is_edh=DHE_DSS_WITH_AES_128_CBC_SHA     is_edh=DHE_DSS_WITH_AES_128_SHA \
	is_exp=0x03000062 is_exp=EXP-DES-56-SHA is_exp=EXP1024-DES-CBC-SHA \
	is_exp=RSA_EXPORT1024_WITH_DES_CBC_SHA \
	is_rc4=0x03000018 is_rc4=ADH-RC4-MD5    is_rc4=DHanon-RC4-MD5 \
	is_rc4=ADH_RC4_128_MD5        is_rc4=DH_anon_WITH_RC4_MD5 \
	is_rc4=DH_anon_WITH_RC4_128_MD5 \
	is_adh=invalid  is_cbc=invalid is_edh=invalid  is_exp=invalid \
	find_name=ECDHE-ECDSA-CHACHA20-POLY1305-SHA256 \
	find_names=DHE-PSK-AES128 find_keys=DHE-PSK-AES128
    # only $(LIST.lib-Ciphers.pm-cmd) is tested here, as they all produce the
    # same output as $(LIST.lib-Ciphers--test)

# some command and options supported by Ciphers.pm are supported by $(SRC.pl)
# too, but must be used there as  --test-ciphers-*
# following generated list contains following commands unknown to Ciphers.pm:
#    --test-ciphers-version --test-ciphers-get_keys_list --test-ciphers-get_keys_list
# doesn't harm, they produce nearly emty output
LIST.lib-Ciphers--test := $(LIST.lib-Ciphers.pm-cmd:%=--test-ciphers-%)
LIST.o-saft.pl         += $(LIST.lib-Ciphers--test)

LIST.lib-options       := version +VERSION --usage
    # these options should be implemented in all tools

LIST.lib-OCfg.pm       := $(LIST.lib-options)

LIST.lib-OData.pm      := $(LIST.lib-options) \
	check_cert  check_conn  check_dest  check_http  check_size \
	checks      data        shorttexts

LIST.lib-ODoc.pm       := $(LIST.lib-options) \
	get-custom      get-markup      get-section     list  get

# tests are functionally the same as testarg-hlp--help-* from Makefile.hlp
LIST.lib-OMan.pm       := $(LIST.lib-options) \
	FAQ     WHY     CHECK   alias   check   cmds    commands compliance \
	content data    glossar intern  help    hint    legacy   links      \
	opt     options ourstr  pattern range   regex   rfc      text       \
	cmd     info    toc     todo    tools   exit    abbr     warnings \
	cfg-check   cfg-data    cfg-hint    cfg-info    cfg-text cfg-regex  \
	gen-wiki    gen-html    gen-cgi     gen-pod     gen-man \
    # lib-OMan.pm allows any of the above listed arguments like:
    #   lib-OMan.pm toc
    #   lib-OMan.pm --help=toc
    #   lib-OMan.pm --test-toc
    # only the first form is tested here, as they all produce the same output

LIST.lib-SSLinfo.pm-t  := \
	--test-openssl --test-sclient --test-sslmap \
	--test-methods --test-ssleay

LIST.lib-OTrace.pm     := $(LIST.lib-options) \
	--tests $(LIST.lib-SSLinfo.pm-t)  --test-memory --test-regex \
	--test-avail --test-init --test-maps --test-prot --test-vars \
	--test-methods  --test-sclient  --test-sslmap   --test-ssleay
# $(O_LIB.dir)/OTrace.pm doesn't handle the options, hence call o-saft.pl with them
LIST.o-saft.pl         += $(LIST.lib-OTrace.pm)

LIST.lib-SSLinfo.pm    := $(LIST.lib-options)  localhost $(LIST.lib-SSLinfo.pm-t)
LIST.lib-SSLhello.pm   := $(LIST.lib-options)  --test-init --test-constant --test-parameter
#LIST.o-saft.pl        += $(LIST.lib-SSLinfo.pm-t)

# command and checks "NOT YET IMPLEMENTED" are hardcoded here,
# should be the same as cfg{commands_notyet} in $(O_LIB.dir)/OCfg.pm
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

# generate targets for all *pm and SRC.pl
ifndef mod-macros-generated
    $(foreach _prg, $(SRC.pm) $(SRC.pl),\
        $(call GEN.targets-init,testarg,mod,$(_prg),LIST.$(subst /,-,$(_prg))) \
    )
    undefine _prg
endif

# some special adaptions to generated targets

# $(O_LIB.dir)/ODoc.pm function needs a file where to read the information
# it's found automatically when using o-saft.pl but not with $(O_LIB.dir)/ODoc.pm
testarg-mod-lib-ODoc.pm_%:      TEST.args   = help.txt

# $(O_LIB.dir)/OTrace.pm does not make sense without a calling parent
testarg-mod-lib-OTrace.pm_%:    EXE.pl      = ../$(SRC.pl)

# more info with pretty printed output: --header
testarg-mod-lib-OMan.pm_%:      TEST.args   = --header

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
