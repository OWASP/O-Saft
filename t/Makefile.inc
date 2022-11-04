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
#?      @(#) Makefile.inc 1.32 22/11/04 19:59:37
#?
#? AUTHOR
#?      18-may-18 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

_SID.inc       := 1.32

_MYSELF.inc    := t/Makefile.inc
ALL.includes   += $(_MYSELF.inc)
ALL.inc.type   += inc

.DEFAULT:
	@echo "**ERROR: unknown target: $(MAKECMDGOALS)"

#_____________________________________________________________________________
#________________________________________________________________ variables __|

HELP.inc        = $(_NL)\
\# Makefile to define required macros. It does not contain targets.    $(_NL)\
\# Note that all definitions herein should be idempotent, so that this $(_NL)\
\# file could be included several times. That's why only  =  and no  +=$(_NL)\
\# assignments are used. $(_NL)\

# ensure that messages and sorting are the same, important to compare results
LANG=C

ifndef Project
    Project    := o-saft
endif

ifndef ProjectName
    ProjectName := O-Saft
endif

ifndef TEST.host
    TEST.host  := localhost
endif

ifndef TEST.init
    TEST.init  := --header
endif

ifndef TEST.dir
    TEST.dir   := t
endif

ifndef TEST.logdir
    TEST.logdir = $(TEST.dir)/log
endif

ifndef TEST.logtxt
    TEST.logtxt = <<random value replaced by make>>
endif

ifndef TMP.dir
    TMP.dir     = /tmp/$(Project)
endif

ifndef SRC.pl
    SRC.pl     := o-saft.pl
endif

ifndef SRC.cgi
    SRC.cgi    := o-saft.cgi
endif

ifndef SRC.tcl
    SRC.tcl    := o-saft.tcl
endif

ifndef DEV.pl
    DEV.pl     := yeast.pl
endif

ifndef MAKEFILE
    MAKEFILE    = $(firstword $(MAKEFILE_LIST))
        # Define a variable for myself, it is the first file in MAKEFILE_LIST.
        # $(MAKEFILE)  will be used where  any makefile is possible.
        # Makefile  is used when exactly Makefile file is meant.
        # $(ALL.Makefiles)  is used, when all makefiles are needed.  Existence
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
    MAKEFLAGS  := --no-builtin-variables --no-builtin-rules --no-print-directory
endif

ifndef OSAFT_MAKE
    export OSAFT_MAKE := avoid writing random data (like date and time string)
endif

ifndef EXE.echo
    EXE.echo   := /bin/echo -e
endif

ifndef EXE.pl
    EXE.pl     := o-saft.pl
endif

ifndef EXE.tcl
    EXE.tcl    := o-saft.tcl
endif

ifndef EXE.docker
    EXE.docker := o-saft-docker
endif

ifndef EXE.dummy
    EXE.dummy  := /bin/echo -n ""
endif

ifndef EXE.log-filterarg
    EXE.log-filterarg  := cat
endif

ifndef EXE.log-iltercmd
    EXE.log-filtercmd  := cat
endif

ifndef _EXE.sort-opt
    _EXE.sort-opt      := -n -f
endif

ifndef _EXE.perldoc-opt
    _EXE.perldoc-opt   := -n nroff -T
endif

ifndef _EXE.pod2man-opt
    _EXE.pod2man-opt   := --utf8 
endif

ifndef TAB
    TAB        := \\011
endif

ifndef _NL
    _NL        := \\012
endif

ifndef _CR
    _CR        := \\015
endif

# also set pseudo macro .SUFFIXES empty (in the hope, it's never needed)
.SUFFIXES:
