#! /usr/bin/make -rRf
#?
#? NAME
#?      Makefile.inc    - define missing macros for Makefile
#?
#? SYNOPSYS
#?      ifndef ALL.Makefiles
#?          include Makefile.inc
#?      endif
#?
#? DESCRIPTION
#?      Defines general macros used in Makefile if they are missing.
#?
#? VERSION
#?      @(#) Makefile.inc 1.2 18/06/08 12:23:41
#?
#? AUTHOR
#?      18-may-18 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

_SID.inc        = 1.2

#_____________________________________________________________________________
#________________________________________________________________ variables __|

# NOTE: all definitions herein should be idempotent, so that this file could be
#       included sevaral times. That's why only  =  and no  +=  assignments are
#       used.

ifndef Project
Project         = o-saft
endif

ifndef ProjectName
endif
ProjectName     = O-Saft

ifndef TEST.host
TEST.host       = localhost
endif

ifndef TMP.dir
TMP.dir         = /tmp/$(Project)
endif

ifndef MAKEFILE
MAKEFILE        = Makefile
endif
# define variable for myself, it allows to use some targets with an other files
# Note  that  $(MAKEFILE)  is used where any Makefile is possible and  Makefile
#       is used when exactly Makefile file is meant.  $(ALL.Makefiles) is used,
#       when all Makefiles are needed. Existance of  ALL.Makefiles  can also be
#       used to check if this file should be included.

ifndef ALL.Makefiles
ALL.Makefiles   = Makefile
endif

# internal used tools (paths hardcoded!)
ifndef MAKE
MAKE            = $(MAKE_COMMAND)
endif

ifndef ECHO
ECHO            = /bin/echo -e
endif

ifndef EXE.pl
EXE.pl          = o-saft.pl
endif

ifndef TAB
TAB             = \\011
endif

ifndef _NL
_NL             = \\012
endif

ifndef _CR
_CR             = \\015
endif
