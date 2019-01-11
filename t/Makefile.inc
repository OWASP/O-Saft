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
#?      @(#) Makefile.inc 1.11 19/01/11 22:55:01
#?
#? AUTHOR
#?      18-may-18 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

_SID.inc        = 1.11

ALL.includes   += t/Makefile.inc
ALL.inc.type   += inc

#_____________________________________________________________________________
#________________________________________________________________ variables __|

# NOTE: all definitions herein should be idempotent, so that this file could be
#       included sevaral times. That's why only  =  and no  +=  assignments are
#       used.

ifndef Project
    Project     = o-saft
endif

ifndef ProjectName
    ProjectName = O-Saft
endif

ifndef TEST.host
    TEST.host   = localhost
endif

ifndef TEST.init
    TEST.init   = --header
endif

ifndef TEST.dir
    TEST.dir    = t
endif

ifndef TEST.logdir
    TEST.logdir = $(TEST.dir)/log
endif

ifndef TMP.dir
    TMP.dir     = /tmp/$(Project)
endif

ifndef SRC.pl
    SRC.pl      = o-saft.pl
endif

ifndef SRC.cgi
    SRC.cgi     = o-saft.cgi
endif

ifndef SRC.tcl
    SRC.tcl     = o-saft.tcl
endif

ifndef DEV.pl
    DEV.pl      = yeast.pl
endif

ifndef MAKEFILE
    MAKEFILE    = $(firstword $(MAKEFILE_LIST))
        # Define a variable for myself, it is the first file in MAKEFILE_LIST.
        # $(MAKEFILE)  will be used where  any makefile is possible.
        # Makefile  is used when exactly Makefile file is meant.
        # $(ALL.Makefiles)  is used, when all makefiles are needed.  Existance
        # of  ALL.Makefiles  can also be used to check if  this file should be
        # included.
endif

ifndef ALL.Makefiles
    MAKE        = $(MAKE_COMMAND) -f $(firstword $(MAKEFILE_LIST))
        # Redefine  MAKE  with proper makefile if not called from  ../Makefile
        # makefile given with -f option is first in  MAKEFILE_LIST,  usually
endif

# internal used tools (paths hardcoded!)
ifndef MAKE
    MAKE        = $(MAKE_COMMAND)
endif

ifndef MAKEFLAGS
    MAKEFLAGS   = --no-builtin-variables --no-builtin-rules --no-print-directory
endif

ifndef ECHO
    ECHO        = /bin/echo -e
endif

ifndef EXE.pl
    EXE.pl      = o-saft.pl
endif

ifndef TAB
    TAB         = \\011
endif

ifndef _NL
    _NL         = \\012
endif

ifndef _CR
    _CR         = \\015
endif

# also set pseudo macro .SUFFIXES empty (in the hope, it's never needed)
.SUFFIXES:
