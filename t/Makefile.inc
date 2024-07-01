#!/usr/bin/make -rRf
#?
#? NAME
#?      Makefile.inc    - define missing variables for Makefile
#?
#? SYNOPSYS
#?      ifndef ALL.Makefiles
#?          include Makefile.inc
#?      endif
#?
#? DESCRIPTION
#?      Defines general variables used in Makefile if they are missing.
#?
#? VERSION
#?      @(#) Makefile.inc 3.9 24/07/01 16:29:03
#?
#? AUTHOR
#?      18-may-18 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

O-SID.inc          := 3.9
O-SELF.inc         := t/Makefile.inc
ALL.includes       += $(O-SELF.inc)
ALL.inc.type       += inc

.DEFAULT:
	@echo "**ERROR: unknown target: $(MAKECMDGOALS)"

#_____________________________________________________________________________
#________________________________________________________________ variables __|

HELP.inc        = $(O-NL)\
\# Makefile to define required variables. It does not contain targets. $(O-NL)\
\# Note that all definitions herein should be idempotent, so that this $(O-NL)\
\# file could be included several times. That's why only  =  and no  +=$(O-NL)\
\# assignments are used. $(O-NL)\

# ensure that messages and sorting are the same, important to compare results
LANG           := C
LC_CTYPE       := C.UTF-8

O-Project      ?= o-saft
O-ProjectName  ?= O-Saft
TEST.host      ?= localhost
TEST.init      ?= --header
TEST.dir       ?= t
TEST.logdir     = $(TEST.dir)/log
TEST.logtxt     = <<random value replaced by make>>
O-TMP.dir       = /tmp/$(O-Project)
SRC.sh         ?= o-saft
SRC.pl         ?= o-saft.pl
SRC.cgi        ?= o-saft.cgi
SRC.tcl        ?= o-saft.tcl

# Define a variable for myself, it is the first file in MAKEFILE_LIST.
# $(MAKEFILE)  will be used where  any makefile is possible.
# Makefile  is used when exactly Makefile file is meant.
# $(ALL.Makefiles)  is used, when all makefiles are needed.
# Existence of  ALL.Makefiles  can also be used to check  if this file should
# be included.
MAKEFILE        = $(firstword $(MAKEFILE_LIST))
MAKE            = $(MAKE_COMMAND)
ifndef ALL.Makefiles
    MAKE        = $(MAKE_COMMAND) -f $(firstword $(MAKEFILE_LIST))
        # Redefine  MAKE  with proper makefile if not called from  ../Makefile
        # makefile given with -f option is first in  MAKEFILE_LIST,  usually
endif
MAKEFLAGS      ?= --no-builtin-variables --no-builtin-rules --no-print-directory

# internal used tools (paths hardcoded!) and their options
export OSAFT_MAKE ?= avoid writing random data (like date and time string)
EXE.echo       ?= /bin/echo -e
EXE.pl         ?= o-saft.pl
EXE.tcl        ?= o-saft.tcl
EXE.o_docker   ?= o-saft-docker
EXE.docker     ?= docker
EXE.dummy      ?= /bin/echo -n ""
EXE.log-filterarg  ?= cat
EXE.log-filtercmd  ?= cat
_EXE.sort-opt      ?= -n -f
_EXE.perldoc-opt   ?= -n nroff -T
_EXE.pod2man-opt   ?= --utf8 

# some spezial characters
O-TAB          ?= \\011
O-NL           ?= \\012
O-CR           ?= \\015

# also set pseudo variable .SUFFIXES empty (in the hope, it's never needed)
.SUFFIXES:
