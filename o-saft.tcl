#!/bin/sh
## restarts using wish \
exec wish "$0" ${1+"$@"}

#!#############################################################################
#!#             Copyright (c) Achim Hoffmann, sic[!]sec GmbH
#!#----------------------------------------------------------------------------
#!# If this tool is valuable for you and we meet some day,  you can spend me an
#!# O-Saft. I'll accept good wine or beer too :-). Meanwhile -- 'til we meet --
#!# your're encouraged to make a donation to any needy child you see.   Thanks!
#!#----------------------------------------------------------------------------
#!# This software is provided "as is", without warranty of any kind, express or
#!# implied,  including  but not limited to  the warranties of merchantability,
#!# fitness for a particular purpose.  In no event shall the  copyright holders
#!# or authors be liable for any claim, damages or other liability.
#!# This software is distributed in the hope that it will be useful.
#!#
#!# This  software is licensed under GPLv2.
#!#
#!# GPL - The GNU General Public License, version 2
#!#                       as specified in:  http://www.gnu.org/licenses/gpl-2.0
#!#      or a copy of it https://github.com/OWASP/O-Saft/blob/master/LICENSE.md
#!# Permits anyone the right to use and modify the software without limitations
#!# as long as proper  credits are given  and the original  and modified source
#!# code are included. Requires  that the final product, software derivate from
#!# the original  source or any  software  utilizing a GPL  component, such  as
#!# this, is also licensed under the same GPL license.
#!#############################################################################

#? NAME
#?      $0 - simple GUI for o-saft.pl
#?
#? SYNOPSIS
#?      $0 [host:port] [host:port] ...
#?
#? DESCRIPTION
#?      This is a simple GUI for  O-Saft - OWASP SSL advanced forensic tool.
#?      The GUI supports all commands (Commands TAB) and options (Options TAB)
#?      available in  o-saft.pl. For each command  o-saft.pl  will be executed
#?      as specified. Results are printed in a new TAB of the GUI. A filter to
#?      markup some important texts is applied to the results in the GUI. This
#?      filter can be modified and extended in the  Filter TAB.
#?      Each TAB with results has a  Filter  button which opens a window where
#?      the visibility of filtered texts (see Filter TAB) can be toggeled.
#?      All results and settings (commands and options) can be saved to files.
#?
#?   Help
#?      All functionallity is documented with balloon help on each checkbutton,
#?      input field, button or table header line.
#?
#?   Examples for filter
#?      Match complete line containing Certificate:
#?         r=1 e=0 #=0 Regex=Certificate
#?      Match word Target:
#?         r=0 e=1 #=6 Regex=Target
#?      Match label text and emphase:
#?         r=1 e=0 #=1 Regex=^[A-Za-z][^:]*\s* Font=osaftHead
#?
#?   Configuration
#?      Some parts of the GUI, for example widget fonts or widget label texts,
#?      can be customized in  .o-saft.tcl.  which  will be searched for in the
#?      user's  HOME directory  and in the local directory.
#?      Please see  .o-saft.tcl  itself for details. A sample  .o-saft.tcl  is
#?      available in the contrib/ directpry.
#?
#?   Copy Texts
#?      All texts visible in the GUI,  wether a label, a button, an entry or a
#?      text itself can be copied to the systems clipboard with:
#?         <Control-ButtonPress-1>
#?      For debugging  <Shift-Control-ButtonPress-1>   will prefix the text by
#?      the pathname and the class of the object containing the text.
#?      Keep in mind that it also copies the huge text in the help window.
#?      The text will be copied to the (ICCCM) buffer CLIPBOARD.  This ensures
#?      that it will not interfere with the usual copy&paste buffer  PRIMARY.
#?      <ButtonPress-1> is the "select button", usually the left mouse button.
#?
#? OPTIONS
#?      --v  print verbose messages (for debugging)
#?
#? KNOWN PROBLEMS
#?      The markup defined in the filters (see Filter TAB) may not yet produce
#?      perfect layouts for the results and the help texts,  to be improved in
#?      many ways. 
#?      Note that the markup is independent of the results and does not change
#?      them, just "highlight" texts of the results.
#?
#? ARGUMENTS
#?      All arguments, except  --help  and  --v,  are treated as a hostname to
#?      be checked.
#?
#. LAYOUT
#.           +---------------------------------------------------------------+
#.       (H) | Host:Port [________________________________________]  [+] [-] |
#.           |                                                               |
#.       (C) | [Start] [+info] [+check] [+cipher] [+quick] [+vulns]      [?] |
#.           |---------------------------------------------------------------|
#.           | +----------++---------++----------++----------+               |
#.       (T) | | Commands || Options || Filter || (n) +cmd || (m) +cmd |     |
#.           | +          +------------------------------------------------+ |
#.           | |                                                           | |
#.           | |                                                           | |
#.           | +-----------------------------------------------------------+ |
#.           |---------------------------------------------------------------|
#.       (S) | |                                                           | |
#.           +---------------------------------------------------------------+
#.
#.      Description
#.       (H) - Frame containing hostnames to be checked
#.       (C) - Buttons for most commonly used commands
#.       (T) - Frame containing panes for commands, options, filter, results.
#.       (S) - Frame containing Status messages
#.
#.      Filter TAB Description
#.           +---------------------------------------------------------------+
#.       (f) |    Key     r  e  #  Regex  Foreground Background  Font     u  |
#.           | +---------+--+--+--+------+----------+----------+--------+--- |
#.       (F) | |== CMT    *  o  0  ^==*               gray      osaftHead x  |
#.           | +---------+--+--+--+------+----------+----------+--------+--- |
#.           | ...                                                           |
#.           +---------------------------------------------------------------+
#.
#.       (f) - Headline for filter description
#.             key        - unique key for this filter
#.             r          - Regex used as regular expression
#.             e          - Regex used as exact match
#.             #          - Nr. of characters to be matched by Regex
#.             Foreground - colour for matched text
#.             Background - colour for background of matched text
#.             Font       - use this font for matched text
#.             u          - matched text will be underlined
#.       (F) - Filter settings
#.             example of a filter
#.
#. LIMITATIONS
#.      Options do not work on Windows. Cumbersome workaround:
#.        # edit o-saft.tcl and set cfg(VERB) 1
#.        start wish
#.        source o-saft.tcl
#.
#. HACKER's INFO
#.   Hash-bang line
#.      The usual way on *IX systems to start a Tcl- script independent of the
#.      platform and underlaying shell would be like:
#.          #!/usr/bin/wish
#.          exec wish "$0" ${1+"$@"}
#.      but above exec will throw erros on Mac OS X, henc a quick&dirt version
#.          exec wish "$0" --
#.      need to be used.  Unfortunatelly this does not allow to pass arguments
#.      on command line. Hence the initial hash-bang line uses   /bin/sh  .
#.
#.   Data used to build GUI
#.      Generation of all objects (widgets in Tk slang) is done  based on data
#.      provided by  o-saft.pl  itself, in praticular some  --help=*  options,
#.      see  CONFIGURATION  below. Output of these  --help=*  must be one item
#.      per line, like:
#.          This is a label, grouping next lines
#.          +command1   Command nr 1
#.          +command2   Command nr 2
#.          Options for commands
#.          --opt1      this options does something
#.      This tools relies on the format of these lines. If the format changes
#.      commands and options may be missing in the generated GUI.
#.      Following options are used:  --help  --help=opt  --help=commands
#.      A detailed example of the format can be found in  proc create_win().
#.
#.      The tool will only work if o-saft.pl is available and executes without
#.      errors. All commands and options of  o-saft.pl  will be available from
#.      herein, except:
#.          - all "--help*" options (as they make no sense here)
#.          - "+cgi" and "+exec" command (they are for internal use only)
#.
#.   Some nameing conventions
#.       - procedures:
#.          create_*    - create widget or window
#.          osaft_*     - run external  o-saft.pl  (and process output)
#.       - variables:
#.          osaft-      - prefix used for all text tags
#.          f_*         - prefix used for all filter list variables
#.          txt         - a text widget
#.          w           - any widget
#.          parent      - parent widget (may be toplevel)
#.          hosts()     - global variable with list of hosts to be checked
#.          cfg()       - global variable containing most configurations
#.          cfg_color() - global variable containing colours for widgets
#.          cfg_label() - global variable containing texts for widgets
#.          cfg_tipp()  - global variable containing texts for tooltips
#.          myX()       - global variable for windows and window manager
#.
#.   Notes about Tcl/Tk
#.      We try to avoid platform-specific code. The only exceptions (2015) are
#.      the perl executable and the start method of the external browser.
#.      All external programs are started using Tcl's  {*}  syntax.
#.      If there is any text visible, we want to copy&paste it.  Therfore most
#.      texts are placed in Tk's text widget instead of a label widget, 'cause
#.      text widgets allow selecting their content by default, while labels do
#.      not.
#.
#.      This is no academically perfect code, but quick&dirty scripted:
#.       - makes use of global variables instead of passing parameters etc..
#.       - mixes layout and functions and business logic
#.       - some widget names are hardcoded
#.
#? VERSION
#?      @(#) 1.74 Winter Edition 2015
#?
#? AUTHOR
#?      04. April 2015 Achim Hoffmann (at) sicsec de
#?
#?      Project Home: https://www.owasp.org/index.php/O-Saft
#?      Help Online:  https://www.owasp.org/index.php/O-Saft/Documentation
#?      Repository:   https://github.com/OWASP/O-Saft
#?
# -----------------------------------------------------------------------------

package require Tcl     8.5
package require Tk      8.5

#_____________________________________________________________________________
#____________________________________________________________ configuration __|

set cfg(SID)    {@(#) o-saft.tcl 1.74 16/06/29 23:35:14 Sommer Edition 2016}
set cfg(TITLE)  {O-Saft}
set cfg(RC)     {.o-saft.tcl}

#-----------------------------------------------------------------------------{
#   this is the only section where we know about o-saft.pl
#   all settings for o-saft.pl go here
set cfg(DESC)   {CONFIGURATION o-saft.pl}
set cfg(SAFT)   {o-saft.pl};    # name of O-Saft executable
set cfg(INIT)   {.o-saft.pl};   # name of O-Saft's startup file
set cfg(.CFG)   {}; # set below and processed in osaft_init
catch {
  set fid [open $cfg(INIT) r]
  set cfg(.CFG) [read $fid];    close $fid; # read .o-saft.pl
}
#-----------------------------------------------------------------------------}

## configure GUI

variable logo [image create photo -data {
  R0lGODlhGAAYAOMOAAAAAAARAQASAQASAgATAQATAgBwLgCBNgCBNwCCNQCCNgCCNwCDNiZ/AP//
  /////yH5BAEKAA8ALAAAAAAYABgAAASE8MlJq6o4W3W1fwvHfZ6oLKRmfkKLmcnTDlRrv6IEBC0g
  2YXMStf7CWiPnETUqAl8suNylFROilHkanh9GpEME9cInU3EVvJ3gkB3umXppCHGYM2UeuUuP4/V
  WRUJHAcZfEgpgHh5b3teUYsmTV1YBDYCfhwGTlgTA4iSFANQJAccKB8RADs=
}]; # [!] 24x24

set cfg(FAST)   {{+check} {+cipher} {+info} {+quick} {+protocols} {+vulns}}; # quick access commands

set cfg(TIP)    [catch { package require tooltip} tip_msg];  # 0 on success, 1 otherwise!

set myX(DESC)   {CONFIGURATION window manager geometry}
#   set minimal window sizes to be usable in a 1024x768 screen
#   windows will be larger if the screen supports it (we rely on "wm maxsize")
set myX(geoO)   "600x720-0+0";  # geometry and position of Help    window
set myX(geo-)   "";             # 
set myX(geoS)   "700x720";      # geometry and position of O-Saft  window
set myX(geoA)   "600x610";      # geometry and position of About   window
set myX(geoF)   "";             # geometry and position of Filter  window (computed dynamically)
set myX(geoT)   "";             # 
set myX(minx)   700;            # O-Saft  window min. width
set myX(miny)   720;            # O-Saft  window min. height
set myX(lenl)   15;             # fixed width of labels in Options window
set myX(rpad)   15;             # right padding in the lower right corner
set myX(padx)   5;              # padding to right border
#   configure according real size
set __x         [lindex [wm maxsize .] 0]
set __y         [lindex [wm maxsize .] 1]
if {$__y < $myX(miny)} { set myX(miny) $__y  }
if {$__x < $myX(minx)} { set myX(minx) $__x  }
if {$__x > 1000 }      { set myX(minx) "999" }
set myX(geoS)   "$myX(minx)x$myX(miny)"

#   myX(buffer) ... NOT YET USED
set myX(buffer) PRIMARY;        # buffer to be used for copy&paste GUI texts
                                # any ICCCM like: PRIMARY, SECONDARY or CLIPBOARD
                                # or: CUT_BUFFER0 .. CUT_BUFFER7
                                # Hint for X, in particular xterm: .Xresources:
                                #     XTerm*VT100.Translations: #override \
                                #         ... \
                                #         <Btn2Up>: insert-selection(PRIMARY,CLIPBOARD) \
                                #         ... \

array set cfg_color {
    DESC        {CONFIGURATION colours used in GUI}
    osaft       gold
    close       orange
    start       yellow
    save        lightgreen
    button      lightyellow
    code        lightgray
    link        blue
    status      wheat
}

array set cfg_label {
    DESC        {CONFIGURATION texts used in GUI for buttons or labels}
    about       About
    close       Close
    closetab    {Close TAB}
    color       {Color Chooser}
    font        {Font Chooser}
    filter      Filter
    minus       {-}
    plus        {+}
    quest       {?}
    quit        Quit
    reset       Reset
    start       Start
    save        Save
    host        {Host[:Port]}
    hideline    {Hide complete line}
    c_toggle    "toggle visibility\nof various texts"
}

array set cfg_tipp {
    DESC        {CONFIGURATION texts used in GUI for tool tips}
    minus       {Remove this line for a host}
    plus        {Add new line for a host}
    help        {Open window with complete help}
    closeme     {Close program}
    closetab    {Close this TAB}
    closew      {Close window}
    saveto      {Save result to file}
    savetofile  {Save configuration to file}
    showfilterconfig {Show configuration for filtering results}
    resetfilterconfig "Reset configuration to values from $cfg(INIT)"
    hideline    {Hide complete line instead of pattern only}
    settings    {Open window with more settings}
    choosecolor {Open window to choose a color}
    choosefont  {Open window to choose a font}
    choosen     {Choosen value for}
    start       "Start $cfg(SAFT) with command "
        # FIXME: $cfg(SAFT) may be changed when reading $cfg(RC) below
    tabCMD      {
Select commands. All selected commands will be executed with the "Start" button.
}
    tabOPT      {
Select and configure options. All options are used for any command button.
}
    tabFILTER   {
Configure filter for text markup: r, e and # specify how the Regex should work;
Forground, Background, Font and u  specify the markup to apply to matched text.
Changes apply to next +command.
}

    DESC_misc   {CONFIGURATION texts used in GUI for various other texts}
    f_key       Key
    f_moder     r
    f_modee     e
    f_chars     {#}
    f_regex     Regex
    f_fg        Foreground
    f_bg        Background
    f_font      Font
    f_u         u
}

# Note: Text for tab* contain new lines.

set cfg(PERL)   {};             # full path to perl; empty on *nix
if {[regexp {indows} $tcl_platform(os)]} {
    # Some platforms are too stupid to run our executable cfg(SAFT) directly,
    # they need a proper perl executable to do it.  We set a default path and
    # then check if it is executable.  If it is not, ask the user to choose a
    # proper one. There are  no more checks  for the selected file.  If it is
    # wrong, the script will bail out with an error later.
    set cfg(PERL)   {c:/programs/perl/perl/bin/perl.exe}
    if {![file executable $cfg(PERL)]} {
        set cfg(PERL) [tk_getOpenFile -title "Please choose perl.exe" ]
    }
}
# NOTE:  as Tcl is picky about empty variables, we have to ensure later, that
# $cfg(PERL) is evaluated propperly,  in particular when it is empty.  We use
# Tcl's  {*}  evaluation for that.

set cfg(CONF)   {internal data storage}
set cfg(CDIR)   [file join [pwd] [file dirname [info script]]]
set cfg(EXEC)   0;  # count executions, used for object names
set cfg(x--x)   0;  # each option  will have its own entry (this is a dummy)
set cfg(x++x)   0;  # each command will have its own entry (this is a dummy)
set cfg(objN)   ""; # object name of notebook; needed to add more note TABS
set cfg(winA)   ""; # object name of About  window
set cfg(winH)   ""; # object name of Help   window
set cfg(winF)   ""; # object name of Filter window
set cfg(objS)   ""; # object name of status line
set cfg(VERB)   0;  # set to 1 to print more informational messages from Tcl/Tk
set cfg(browser) "";            # external browser program, set below

#   search browser, first matching will be used
set __native    "";
switch [tk windowingsystem] {   # ugly workaround to detect special start methods
    "aqua"  { set __native "open"  }
    "Aqua"  { set __native "open"  }
    "win32" { set __native "start" }
    "win64" { set __native "start" }
    *       { set __native ""      }
}
foreach b " $__native \
            firefox chrome chromium iceweasel konqueror mozilla \
            netscape opera safari webkit htmlview www-browser w3m \
          " {
    set binary [lindex [auto_execok $b] 0]; # search in $PATH
    #dbx# puts "browser: $b $binary"
    if {[string length $binary]} {
        set cfg(browser) $binary
        break
    }
}

set cfg(AQUA)   "CONFIGURATION Aqua (Mac OS X)"
#   Tcl/Tk on Aqua has some limitations and quirky behaviours
#      myX(rpad)    # used as right padding for widgets in the lower right
                    # corner where there is Aqua's resize icon

set hosts(0)    0;  # array containing host:port; index 0 contains counter
set tab(0)      ""; # contains results of cfg(SAFT)

#_____________________________________________________________________________
#_______________________________________________________ filter definitions __|

#   array name  {description of element used in header line in Filter tab}
set f_key(0)    {Unique key for regex}
set f_mod(0)    {Modifier how to use regex}
set f_len(0)    {Length to be matched (0 for complete line)}
set f_bg(0)     {Background color used for matching text (empty: don't change)}
set f_fg(0)     {Foreground color used for matching text (empty: don't change)}
set f_fn(0)     {Font used for matching text (empty: don't change)}
set f_un(0)     {Underline matching text (0 or 1)}
set f_rex(0)    {Regex to match text}
set f_cmt(0)    {Description of regex}

proc txt2arr {str} {
    #? convert string with filter definitions to arrays
    global f_key f_mod f_len f_bg f_fg f_rex f_un f_fn f_cmt; # lists containing filters
    set k 0
    foreach line [split $str "\n"] {
        if {[regexp "^\s*$" $line]} { continue };   # skip empty lines
        if {[regexp "^#"    $line]} { continue };   # skip comments
        set _l [split [regsub -all {\{\}} $line {}] "\t"]
        incr k
        # scan would be nice, but splits on all whitespaces :-( so we do it the hard way
        set f_key($k) [string trim [lindex $_l 0]]
        set f_mod($k) [lindex $_l 1]
        set f_len($k) [lindex $_l 2]
        set f_bg($k)  [lindex $_l 3]
        set f_fg($k)  [lindex $_l 4]
        set f_fn($k)  [lindex $_l 5]
        set f_un($k)  [lindex $_l 6]
        set f_rex($k) [lindex $_l 7]
        set f_cmt($k) [lindex $_l 8]
    }
}; # txt2arr

#   Filters to match results are defined as tabular text.
#   For better readability we do not use output of  "o-saft.pl +help=ourstr".
#   A tabular string is used, which is better to maintain than  Tcl arrays.
#   This string is converted to multiple arrays (one array for each line in
#   the string), these array can be simple accessed in Tcl.
#   A filter consist of all elements with same index in each array.
#   This also allows to extend the arrays dynamically.
#   First (0) index in each array is description.

#   use map to replace variables (and short names to fit in 8 characters)

txt2arr [string map "
    _lGreen lightgreen
    _yellow yellow
    _orange orange
    _sBlue  SteelBlue
    _lBlue  LightBlue
    _lGray  LightGray
    __bold  osaftHead
    _ME_    $cfg(SAFT)
    " {
# syntax in following table:
#   - lines starting with # as very first character are comments and ignored
#     a # anywhere else is part of the string in corresponding column
#   - columns *must* be separated by exactly one TAB
#   - empty strings in columns must be written as {}
#   - strings *must not* be enclosed in "" or {}
#   - variables must be defined in map above and used accordingly
#   - lines without regex (column f_rex contains {}) will not be applied
#------+-------+-------+-------+-------+-------+-------+-------+-------------------------------
# f_key	f_mod	f_len	f_bg	f_fg	f_fn	f_un	f_rex	description of regex
#------+-------+-------+-------+-------+-------+-------+-------+-------------------------------
  no	-regexp	1	{}	{}	{}	0	no\s*(LO|WE|we|ME|HI)	word 'no' followed by LOW|WEAK|MEDIUM|HIGH
# NOTE   no  has no colours, otherwhise it would mix with filters below
# FIXME  no  must be first regex in liste here, but still causes problems in toggle_txt
  LOW	-exact	3	red	{}	{}	0	LOW	word  LOW   anywhere
  WEAK	-exact	4	red	{}	{}	0	WEAK	word  WEAK  anywhere
  weak	-exact	4	red	{}	{}	0	weak	word  weak  anywhere
 MEDIUM	-exact	6	yellow	{}	{}	0	MEDIUM	word MEDIUM anywhere
  HIGH	-exact	4	_lGreen	{}	{}	0	HIGH	word  HIGH  anywhere
 **WARN	-exact	0	_lBlue	{}	{}	0	**WARN	line  **WARN (warning from _ME_)
  NO	-regexp	1	_orange	{}	{}	0	no \([^)]*\)	word  no ( anywhere
  YES	-regexp	3	_lGreen	{}	{}	0	yes	word  yes  at end of line
 == CMT	-regexp	0	gray	{}	__bold	1	^==*	line starting with  == (formatting lines)
  # DBX	-regexp	0	{}	blue	{}	0	^#[^[]	line starting with  #  (verbose or debug lines)
 #[KEY]	-regexp	2	_lGray	{}	{}	0	^#\[[^:]+:\s*	line starting with  #[keyword:]
# ___                                                                   but not:  # [keyword:
  _ME_	-regexp	0	black	white	{}	0	.*?_ME_.*\n\n	lines contaning program name
 Label:	-regexp	1	{}	{}	__bold	0	^(#\[[^:]+:\s*)?[A-Za-z][^:]*:\s*	label of result string from start of line until :
  perl	-regexp	0	purple	{}	{}	0	^Use of .*perl	lines with perl warnings
  usr1	-regexp	0	{}	{}	{}	0	{}	{}
#------+-------+-------+-------+-------+-------+-------+-------+-------------------------------
#      ** columns must be separated by exactly one TAB **
}]; # filter

#_____________________________________________________________________________
#________________________________________________________________ functions __|

# if {$cfg(TIP)==1} { # use own tooltip from: http://wiki.tcl.tk/3060?redir=1954

proc tooltip {w help} {
    bind $w <Any-Enter> "after 1000 [list tooltip:show %W [list $help]]"
    bind $w <Any-Leave> "destroy %W.balloon"
}; # tooltip

proc tooltip:show {w arg} {
    if {[eval winfo containing  [winfo pointerxy .]]!=$w} {return}
    set top $w.balloon
    catch {destroy $top}
    toplevel $top -bd 1 -bg black
    wm overrideredirect $top 1
    if {[string equal [tk windowingsystem] aqua]}  {
        ::tk::unsupported::MacWindowStyle style $top help none
    }   
    pack [message $top.txt -aspect 10000 -bg lightyellow \
        -font fixed -text $arg]
    set wmx [winfo rootx $w]
    set wmy [expr [winfo rooty $w]+[winfo height $w]]
    wm geometry $top [winfo reqwidth $top.txt]x[
        winfo reqheight $top.txt]+$wmx+$wmy
    raise $top
}; # tooltip:show
# 
# # Example:
# button  .b -text Exit -command exit
# tootip  .b "Push me if you're done with this"
# pack    .b
#
# }

proc create_tip {parent txt} {
    #? add tooltip message to given widget
    global cfg
    if {$cfg(TIP)==1} {     # package tooltip not available, use own one
        tooltip $parent "$txt"
    } else {
        set txt [regsub {^-} $txt " -"];# texts starting with - cause problems in tooltip::tooltip
        tooltip::tooltip $parent "$txt"
    }
}; # create_tip

proc get_color {key} {
    #? return color name for key from global cfg_color variable
    global cfg_color
    return $cfg_color($key)
}; # get_color

proc btn_text {key} {
    #? return text string for key from global cfg_label variable
    global cfg_label
    return $cfg_label($key)
}; # btn_text

proc tip_text {key} {
    #? return text string for key from global cfg_tipp variable
    global cfg_tipp
    return $cfg_tipp($key)
}; # tip_text

proc get_padx {key} {
    #? return padx value for key from global myX variable
    global myX
    return $myX($key)
}; # get_padx

proc str2obj {str} {
    #? convert string to valid Tcl object name; returns new string
    set name [regsub -all {[+]} $str  {Y}];     # commands
    set name [regsub -all {[-]} $name {Z}];     # options (mainly)
    set name [regsub -all {[^a-zA-Z0-9_]} $name {X}];
    set name "o$name";  # first character must be lower case letter
    return $name
}; # str2obj

proc notTOC {str} {
    #? return 0 if string should be part of TOC; 1 otherwise
    if {[regexp {^ *(NOT YET|WYSIW)} $str]} { return 1; };  # skip some special strings
    if {[regexp {^ *$} $str]}               { return 1; };  # skip empty
    #dbx# puts "TOC $str";
    return 0
}; # notTOC

proc jumpto_mark {w txt} { catch { $w see [$w index $txt.first] } }
     # jump to mark in given text widget;
     # we simply ignore any error if index is unknown

proc toggle_cfg {w opt val} {
    #? use widget config command to change options value
    if {$val ne {}} { $w config $opt $val; }
    return 1
}; # toggle_cfg

proc toggle_txt {txt tag val line} {
    #? toggle visability of text tagged with name $tag
    # note that complete line is tagged with name $tag.l (see apply_filter)
    global cfg
    if {$cfg(VERB)==1} { puts "toggle_txt: $txt tag config $tag -elide [expr ! $val]" }
    #if {$line==0} {
        #$txt tag config $tag   -elide [expr ! $val];  # "elide true" hides the text
    #}
    if {[regexp {\-(Label|#.KEY)} $tag]} {
        $txt tag config $tag   -elide [expr ! $val];  # hide just this pattern
        # FIXME: still buggy (see below)
        return;
    }
    # FIXME: if there is more than one tag associated with the same range of
    # characters (which is obviously for $tag and $tag.l), then unhiding the
    # tag causes the $tag no longer accessable. Reason yet unknown.
    # Hence we only support hiding the complete line yet.
    $txt tag config $tag.l -elide [expr ! $val]
}; # toggle_txt

proc update_status {val} {
    #? add text to status line
    global cfg
    $cfg(objS) config -state normal
    $cfg(objS) insert end "$val\n"
    $cfg(objS) see "end - 2 line"
    $cfg(objS) config -state disabled
    update idletasks;       # enforce display update
}

proc apply_filter {txt} {
    #? apply filters for markup in output
    # set tag for all texts mtching pattern from each filter
    # also sets a tag for the complete line named with suffix .l
    global cfg
    global f_key f_mod f_len f_bg f_fg f_rex f_un f_fn f_cmt; # lists containing filters
    foreach {k key} [array get f_key] {
        if {$k eq 0} { continue };
        #set key $f_key($k)
        set mod $f_mod($k)
        set len $f_len($k); # currenty used for 0 only
        set rex $f_rex($k)
        set fg  $f_fg($k)
        set bg  $f_bg($k)
        set nr  $f_un($k)
        set fn  $f_fn($k)
        if {$key eq ""} { continue };   # invalid or disabled filter rules
        if {$rex eq ""} { continue };   # invalid or disabled filter rules
        if {$cfg(VERB)==1} { puts "apply_filter: $key : /$rex/ $mod: bg->$bg, fg->$fg, fn->$fn" }
        # anf contains start, end corresponding end position of match
        set key [str2obj [string trim $key]]
        set anf [$txt search -all $mod -count end "$rex" 1.0] 
        set i 0
        foreach a $anf {
            set e [lindex $end $i];
            incr i
            if {$key eq {NO} || $key eq {YES}} {incr e -1 }; # FIXME very dirty hack to beautify print
            $txt tag add    osaft-$key.l "$a linestart" "$a lineend"
            if {$len==0} {
               $txt tag add osaft-$key    $a            "$a + 1 line - 1 char"
              #$txt tag add osaft-$key    $a            "$a lineend"; # does not work
            } else {
               $txt tag add osaft-$key    $a            "$a + $e c"
            }
            $txt tag  raise osaft-$key.l osaft-$key
        }
        #dbx# puts "$key: $rex F $fg B $bg U $nr font $fn"
        if {$fg ne ""}  { $txt tag config osaft-$key -foreground $fg }
        if {$bg ne ""}  { $txt tag config osaft-$key -background $bg }
        if {$nr ne "0"} { $txt tag config osaft-$key -underline  $nr }
        if {$fn ne ""}  { $txt tag config osaft-$key -font       $fn }
    }
}; # apply_filter

proc www_browser {url} {
    #? open URL in browser, uses system's native browser
    global cfg
    if {[string length $cfg(browser)] < 1} { puts {**WARNING: no browser found}; return; }
    if {$cfg(VERB)==1} {
        puts  { exec {*}$cfg(browser) $url & }
    }
        catch { exec {*}$cfg(browser) $url & } 
}; # www_browser

proc show_window {w} {
    #? show window near current cursor position
    set y   [winfo pointery $w]; incr y 23
    set x   [winfo pointerx $w]; incr x 23
    wm geometry  $w "+$x+$y"
    wm deiconify $w
}; # show_window

proc create_selected {title val} {
    #? opens toplevel window with selectable text
    global cfg myX
    global __var;   # must be global
    set w    .selected
    toplevel $w
    wm title $w "$cfg(TITLE): $title"
    wm geometry  $w 200x50
    pack [entry  $w.e -textvariable __var -relief flat]
    pack [button $w.q -text [btn_text close] -command "destroy $w" -bg [get_color close]] -side right -padx $myX(rpad)
    create_tip   $w.e "[tip_text choosen] $title"
    create_tip   $w.q [tip_text closew]
    set __var "$val"
    return 1
}; # create_selected

proc create_window {title size} {
    #? create new toplevel window with given title and size; returns widget
    global cfg myX
    set this    .[str2obj $title]
    if {[winfo exists $this]}  { return ""; }; # do nothing
    toplevel    $this
    wm title    $this "$cfg(TITLE): $title"
    wm iconname $this "o-saft: $title"
    wm geometry $this $size
    pack [frame $this.f1  -relief sunken  -borderwidth 1] -fill x -side bottom
    pack [button $this.f1.q -text [btn_text close] -bg [get_color close] -command "destroy $this"]    -side right -padx $myX(rpad)
    create_tip   $this.f1.q [tip_text closew]
    if {$title eq "Help" || $title eq {About}} { return $this }
    if {[regexp {^Filter} $title]}             { return $this }
    # all other windows have a header line and a Save button
    pack [frame $this.f0    -borderwidth 1 -relief sunken]     -fill x -side top
    pack [label $this.f0.t  -text $title   -relief flat  ]     -fill x -side left
    pack [button $this.f0.h -text {?} -command "create_help {$title}"] -side right
    pack [button $this.f1.s -text [btn_text save] \
                  -bg [get_color save] -command {osaft_save "CFG" 0}]  -side left
    create_tip   $this.f1.s [tip_text savetofile]
    return $this
}; # create_window

proc create_host {parent} {
    #?  frame with label and entry for host:port; $nr is index to hosts()
    global cfg hosts myX
    set host  $hosts($hosts(0))
    set leftx 0;    # for nice alignments (we do not use grid)
    incr hosts(0)
    if {$hosts(0)==1}  { set leftx 5 }
    if {$cfg(VERB)==1} { puts "create_host: host($hosts(0)): $host" }
    set this $parent.ft$hosts(0)
          frame  $this
    pack [label  $this.lh -text [btn_text host]]       -side left
    pack [entry  $this.eh -textvariable hosts($hosts(0))]  -side left -fill x -expand 1
    pack [button $this.bp -text [btn_text plus]  -command "create_host {$parent};"] -side left
    pack [button $this.bm -text [btn_text minus] -command "remove_host $this; set hosts($hosts(0)) {}"] -side left -padx "$leftx $myX(padx)"
    create_tip   $this.bm [tip_text minus]
    create_tip   $this.bp [tip_text plus]
    if {$hosts(0)==1} {
        # do not remove the first one; instead change the {-} button to {about}
        global logo
        $this.bm config -text {!} -command "create_about" -image $logo -relief flat
        create_tip $this.bm "About $cfg(TITLE)"
    }
    set i [expr $hosts(0) - 1]
    set prev $parent.ft$i
    while {$i > 0} {    # check if previous frame exists, otherwise decrement
        if {[winfo exists $prev]} { break; }
        incr i -1
        set prev $parent.ft$i
    }
    # if we reach here a previous frame exists
    # or i==0 which should never occour and then will force an error in next line
    pack $this -fill x -after $prev
}; # create_host

proc remove_host {w} {
    #? destroy frame with label and entry for host:port
    catch {destroy $w.eh $w.bp $w.bm $w.lh $w}
}; # remove_host

proc create_text {parent txt} {
    #? create scrollable text widget and insert given text; returns widget
    set this    $parent
    text        $this.t -wrap char -yscroll "$this.s set";  # -width 40 -height 10
    scrollbar   $this.s -orient vertical -command "$this.t yview"
    #set txt     [regsub -all {\t} $txt "\t"];   # tabs are a pain in Tcl :-(
    $this.t insert end $txt
    $this.t config -state disabled -font TkFixedFont
    pack $this.s -side right -fill y  -pady 2 -padx {0 2} -in $this
    pack $this.t -fill both -expand 1 -pady 2 -padx {2 0} -in $this
    return $this
}; # create_text

proc create_filter_head {parent txt tip col} {
    #? create a cell for header line in the filter grid
    # note: txt must be the index to cfg_label array, we cannot pass the value
    #       directly because it then must be converted to an object name also,
    #       see next setting of $this
    set this $parent.$txt
    grid [label $this -text [tip_text $txt] -relief raised -borderwidth 1 ] -sticky ew -row 0 -column $col
    create_tip  $this $tip
}; # create_filter_head

proc create_filtertab {parent cmd} {
    #? create table with filter data
    global cfg aaa
    global f_key f_mod f_len f_bg f_fg f_rex f_un f_fn f_cmt; # filters
    pack [label $parent.text -relief flat -text [tip_text tabFILTER]]
    set this $parent.g
    frame $this
    # grid makes nice layouts but is too stupid to resice (expand) the widgets
    # in its cells. Ugly workaround would be to use the widget inside a frame,
    # and this frame as a grid slave. The widget then can be packed inside the
    # frame with the -exapnd and -fill option. A bit cumbersome ...
    # We use another approach: all widgets get a fixed width, the widget which
    # should be resized gets a huge width. This widget is in the column, which
    # should be resized by the grid.  grid honors all specified widths, except
    # that of the column subject for resizing.  Sounds like a bug in grid, but
    # works here :-))
    # { set header line with descriptions
        create_filter_head $this f_key    $f_key(0) 0
        create_filter_head $this f_moder "$f_mod(0) (-regexp)" 1
        create_filter_head $this f_modee "$f_mod(0) (-exact)"  2
        create_filter_head $this f_chars  $f_len(0) 3
        create_filter_head $this f_regex  $f_rex(0) 4
        create_filter_head $this f_fg     $f_fg(0)  5
        create_filter_head $this f_bg     $f_bg(0)  6
        create_filter_head $this f_font   $f_fn(0)  7
        create_filter_head $this f_u      $f_un(0)  8
    # }
    foreach {k key} [array get f_key] { # set all filter lines
        if {$k eq 0} { continue };
        #set key $f_key($k)
        set key [str2obj [string trim $key]]
        set mod $f_mod($k)
        set len $f_len($k)
        set rex $f_rex($k)
        set fg  $f_fg($k)
        set bg  $f_bg($k)
        set nr  $f_un($k)
        set fn  $f_fn($k)
        if {$key eq ""} { continue };   # invalid or disabled filter rules
        if {$cfg(VERB)==1} { puts "create_filtertab: .$key /$rex/" }
        grid [entry   $this.k$k -textvariable f_key($k) -width  8 ] -row $k -column 0
        grid [radiobutton $this.x$k -variable f_mod($k) -width  2 -value "-regexp"  ] -row $k -column 1
        grid [radiobutton $this.e$k -variable f_mod($k) -width  2 -value "-exact"   ] -row $k -column 2
        grid [entry   $this.l$k -textvariable f_len($k) -width  2 ] -row $k -column 3
        grid [entry   $this.r$k -textvariable f_rex($k) -width 65 ] -row $k -column 4
        grid [entry   $this.f$k -textvariable f_fg($k)  -width  9 ] -row $k -column 5
        grid [entry   $this.b$k -textvariable f_bg($k)  -width  9 ] -row $k -column 6
        grid [entry   $this.s$k -textvariable f_fn($k)  -width 10 ] -row $k -column 7
        grid [checkbutton $this.u$k -variable f_un($k)            ] -row $k -column 8
        create_tip  $this.k$k $f_cmt($k)
        create_tip  $this.r$k $f_cmt($k)
        # some entries apply setting to KEY entry
        $this.f$k config -vcmd "toggle_cfg $this.k$k -fg   \$f_fg($k)" -validate focusout
        $this.b$k config -vcmd "toggle_cfg $this.k$k -bg   \$f_bg($k)" -validate focusout
        $this.s$k config -vcmd "toggle_cfg $this.k$k -font \$f_fn($k)" -validate focusout
        toggle_cfg $this.k$k -fg   $f_fg($k)
        toggle_cfg $this.k$k -bg   $f_bg($k)
        toggle_cfg $this.k$k -font $f_fn($k)
    }
    foreach {k key} [array get f_key] { # set all filter lines
        if {$k eq 0} { continue };
        # FIXME: unfortunately this binding executes immediately, which results
        # in a chooseColor window for each row at startup
        #$this.b$k config -vcmd "set f_bg($k) [tk_chooseColor -title $f_bg(0)]; return 1" -validate focusin
        #$this.s$k config -vcmd "tk fontchooser config -command {set f_fn($k)}; tk_chooseColor -title $f_bg(0)]; return 1" -validate focusin
    }
    pack $this -fill x -fill both -expand 1
    set lastrow [lindex [grid size $this] 1]
    #grid rowconfigure    $this [expr $lastrow - 1] -weight 1
    grid columnconfigure $this {0 1 2 3 5 6 7 8} -weight 0
    grid columnconfigure $this 4 -minsize 20 -weight 1; # minsize does not work 
    catch { # silently ignore if systems has no fontchooser (i.e. Mac OS X)
    tk fontchooser config -command {create_selected "Font"}; # what to do with selection
        # there is no tk_fontchooser, but tk::fontchooser or tk fontchooser
    pack [button $parent.fc -text [btn_text font]  -command {tk fontchooser show}] -side right
    create_tip   $parent.fc [tip_text choosefont]
    }
    pack [button $parent.cc -text [btn_text color] -command {create_selected "Color" [tk_chooseColor]} ] -side right
    create_tip   $parent.cc [tip_text choosecolor]
}; # create_filtertab

proc create_filter {txt cmd} {
    #? create new window with filter commands for exec results; store widget in cfg(winF)
    global cfg f_key f_bg f_fg f_cmt filter_bool myX
    if {$cfg(VERB)==1} { puts "create_filter: $txt $cmd"; }
    if {[winfo exists $cfg(winF)]}  { show_window $cfg(winF); return; }
    set geo [split [winfo geometry .] {x+-}]
    set myX(geoF) +[expr [lindex $geo 2] + [lindex $geo 0]]+[expr [lindex $geo 3]+100]
        # calculate new position: x(parent)+width(parent), y(parent)+100
        # most window managers are clever enough to position window
        # correctly if calculation is outside visible (screen) frame
    set cfg(winF) [create_window "Filter:$cmd" $myX(geoF)]
        # FIXME: only one variable for windows, need a variable for each window
        #        workaround see osaft_exec
    set this $cfg(winF)
    #dbx# puts "TXT $txt | $cmd | $myX(geoF)"
    pack [frame $this.f -relief sunken -borderwidth 1] -fill x
    pack [label $this.f.t -relief flat -text [btn_text c_toggle]] -fill x
    pack [checkbutton $this.f.c -text [btn_text hideline] -variable filter_bool($txt,line)] -anchor w;
    create_tip $this.f.c [tip_text hideline]
    $this.f.c config -state disabled ; # TODO: not yet working, see FIXME in toggle_txt
    foreach {k key} [array get f_key] {
        if {$k eq 0} { continue };
        #set key $f_key($k)
        set bg $f_bg($k)
        set fg $f_fg($k)
        set key [str2obj [string trim $key]]
        set filter_bool($txt,osaft-$key) 1; # default: text is visible
        pack [checkbutton $this.x$key \
                    -text $f_key($k) -variable filter_bool($txt,osaft-$key) \
                    -command "toggle_txt $txt osaft-$key \$filter_bool($txt,osaft-$key) \$filter_bool($txt,line);" \
             ] -anchor w ;
        # note: useing $f_key($k) instead of $key as text
        # note: checkbutton value passed as reference
        # TODO: following "-fg white" makes check in checkbox invisible 
        if {$fg ne ""}  { $this.x$key config -fg $fg }; # Tk is picky ..
        if {$bg ne ""}  { $this.x$key config -bg $bg }; # empty colour not allowd
        create_tip $this.x$key "show/hide: $f_cmt($k)"; # FIXME: use tip_text
    }

}; # create_filter

proc create_about {} {
    #? create new window with About text; store widget in cfg(winA)
    #  Show the text starting with  #?  from this file.
    global cfg myX
    if {[winfo exists $cfg(winA)]}  { show_window $cfg(winA); return; }
    set cfg(winA) [create_window {About} $myX(geoA)]
    set txt [create_text $cfg(winA) [osaft_about "ABOUT"]].t
    $txt config -bg [get_color osaft]

    # search for URLs, mark them and bind key to open browser
    set anf [$txt search -regexp -all -count end {\shttps?://[^\s]*} 1.0] 
    set i 0
    foreach a $anf {
        set e [lindex $end $i];
        set t [string trim [$txt get $a "$a + $e c"]];
        set l [string length $t]
        incr i
        $txt tag add    osaft-URL    $a "$a + $e c"
        $txt tag add    osaft-URL-$i $a "$a + $e c"
        $txt tag config osaft-URL-$i -foreground [get_color link]
        $txt tag bind   osaft-URL-$i <ButtonPress> "www_browser $t"
        if {$cfg(TIP)==0} { tooltip::tooltip $txt -tag osaft-URL-$i "Execute $cfg(browser) $t" }
    }
}; # create_about

proc create_help {sect} {
    #? create new window with complete help; store widget in cfg(winH)
    #? if  sect  is given, jump to this section
    # uses plain text help text from "o-saft.pl --help"
    # This text is parsed for section header line (all capital characters)
    # which will be used as Table of Content and inserted before the text.
    # All referenzes to this sections are clickable.
    # Also all references to commands (starting with '+') and options ('-')
    # are highlighted and used for navigation.
    # Example text:
        # ...
        # QUICKSTART
        # 
        #         Before going into  a detailed description  of the  purpose and usage,
        #         here are some examples of the most common use cases:
        # 
        #         * Show supported (enabled) ciphers of target:
        #           o-saft.pl +cipher --enabled example.tld
        # ...
        # OPTIONS
        # 
        #         All options are written in lowercase. Words written in all capital in
        #         the description here is text provided by the user.
        # 
        #     Options for help and documentation
        # 
        #       --help
        # 
        #           WYSIWYG
        # ...
        #
    # In above example  QUICKSTART  and  OPTIONS  are the section headers,
    # --help  is an option and the line starting with  o-saft.pl  will be
    # a command (not to be confused with commands of o-saft.pl).
    # Idea: probably "o-saft.pl --help=wiki" is better suitable for creating
    # the help text herein.
    #
    # TODO: some section lines are not detected properly and hence missing

    global cfg myX
    if {$cfg(VERB)==1} { puts "create_help($sect)" }
    if {[winfo exists $cfg(winH)]} {                    # if there is a window, just jump to text
        wm deiconify $cfg(winH)
        set name [str2obj [string trim $sect]]
        jumpto_mark $cfg(winH).t "osaft-HEAD-$name"
        return
    }
    set this    [create_window {Help} $myX(geoO)]
    set help    [regsub -all {===.*?===} $cfg(HELP) {}];# remove informal messages
    set txt     [create_text $this $help].t
    set toc     {}

    # 1. search for section head lines, mark them and add (prefix) to text
    set anf [$txt search -regexp -nolinestop -all -count end {^ {0,5}[A-Z][A-Za-z_? -]+$} 1.0] 
    set i 0
    foreach a $anf {
        set e [lindex $end $i];
        set t [$txt get $a "$a + $e c"];                # don't trim, we need leading spaces
        set l [string length $t]
        incr i
        if {[notTOC $t]} { continue; };                 # skip some special strings
        if {[string trim $t] eq ""} { continue };       # skip empty entries
        if {[regexp {^[A-Z][A-Z_? -]+$} $t]} { set toc "$toc\n" };  # add empty line for top level headlines
        set toc "$toc\n  $t";                           # prefix headline with spaces in TOC
        set name [str2obj [string trim $t]]
        $txt tag add  osaft-HEAD       $a "$a + $e c"
        $txt tag add  osaft-HEAD-$name $a "$a + $e c"
        #$txt insert $a "\n\[ ^ \]\n";                  # TODO: insert button to top 
    }
    $txt config -state normal
    $txt insert 1.0 "\nCONTENT\n$toc\n"
    $txt tag     add  osaft-LNK    2.0 2.7;             # add markup
    $txt tag     add  osaft-LNK-T  2.0 2.7;             #
    $txt config -state disabled
    set nam [$txt search -regexp -nolinestop {^NAME$} 1.0]; # only new insert TOC

    # 2. search for all references to section head lines in TOC and add click event
    set anf [$txt search -regexp -nolinestop -all -count end { *[A-Za-z_? -]+( |$)} 3.0 $nam] 
    # FIXME: above regex fails for some lines in generated TOC, reason unknown.
    set i 0
    foreach a $anf {
        set e [lindex $end $i];
        set t [$txt get $a "$a + $e c"];
        if {[notTOC $t]} { continue; };                 # skip some special strings
        incr i
        set name [str2obj [string trim $t]]
        set b [$txt search -regexp {[A-Z]+} $a] 
        $txt tag add  osaft-TOC    $b "$b + $e c"; # - 1 c";# do not markup leading spaces
        $txt tag add  osaft-TOC-$i $a "$a + $e c";      # but complete line is clickable
        $txt tag bind osaft-TOC-$i <ButtonPress> "jumpto_mark $txt {osaft-HEAD-$name}"
        #dbxX puts "TAG: $txt {osaft-HEAD-$name}"
    }

#    # 2a. search for all references to section head in text
#    set anf [$txt search -regexp -nolinestop -all -count end { +[A-Z_ -]+( |$)} $nam]
#    # FIXME: returns too much false positives
#    set i 0
#    foreach a $anf {
#        set e [lindex $end $i];
#        set t [$txt get $a "$a + $e c"];
#        incr i
#        if {[regexp {^[A-Z_ -]+$} $t]} { continue };   # skip headlines itself
#        if {[regexp {HIGH|MDIUM|LOW|WEAK|SSL|DHE} $t]} { continue };  # skip false matches
#        if {[notTOC $t]} { continue; }; # skip some special strings
#        $txt tag add    osaft-XXX $a "$a + $e c"
#        $txt tag bind   osaft-XXX-$i <ButtonPress> "jumpto_mark $txt {osaft-LNK-$name}"
#        $txt tag config osaft-XXX    -foreground [get_color link]
#    }

    # 3. search all commands and options and try to set click event
    set anf [$txt search -regexp -nolinestop -all -count end { [-+]-?[a-zA-Z0-9_=+-]+([, ]|$)} 3.0] 
    set i 0
    foreach a $anf {
        set e [lindex $end $i];
        set l [$txt get "$a - 2 c" "$a + $e c + 1 c"];  # one char more, so we can detect head line
        set t [string trim [$txt get $a "$a + $e c"]];
        set r [regsub {[+]} $t {\\+}];  # need to escape +
        set r [regsub {[-]} $r {\\-}];  # need to escape -
        set name [str2obj [string trim $t]]
        if {[regexp -lineanchor "\\s\\s+$r$" $l]} {     # FIXME: dos not match all line proper
            # these matches are assumed the header lines
            $txt tag add    osaft-LNK-$name $a "$a + $e c";
            $txt tag add    osaft-LNK       $a "$a + $e c";
        } else {
            # these matches are assumed references
            $txt tag add    osaft-LNK-$i $a "$a + $e c - 1 c"; # do not markup spaces
            $txt tag bind   osaft-LNK-$i <ButtonPress> "jumpto_mark $txt {osaft-LNK-$name}"
            $txt tag config osaft-LNK-$i -foreground [get_color link]
            $txt tag config osaft-LNK-$i -font osaftSlant
        }
        incr i
    }

    # 4. search for all examles and highlight them
    set anf [$txt search -regexp -nolinestop -all -count end "$cfg(SAFT) \[^\\n\]+" 3.0] 
    set i 0
    foreach a $anf {
        set e [lindex $end $i];
        $txt tag add  osaft-CODE $a "$a + $e c"
        incr i
    }

    # 5. search for all special quoted strings and highlight them
    set anf [$txt search -regexp -nolinestop -all -count end {'[^'\n]+'} 3.0] 
    set i 0
    foreach a $anf {
        set e [lindex $end $i];
        $txt tag add  osaft-CODE $a "$a + $e c"
        incr i
        #regsub -start $a -all {'} $txt { }
    }

    # finaly global markups
    $txt tag config   osaft-TOC  -foreground [get_color link]
    $txt tag config   osaft-HEAD -font osaftBold
    $txt tag config   osaft-TOC  -font osaftBold
    $txt tag config   osaft-LNK  -font osaftBold
    $txt tag config   osaft-CODE -background [get_color code]

    set cfg(winH) $this
}; # create_help

proc create_note {parent title} {
    #? create notebook TAB; returns widget
    set name [str2obj $title]
    set this $parent.$name
    set alt  0
    if {[regexp {^\(} $title]} { set alt 1; }; # don't use (, but next charcter
    frame       $this
    $parent add $this   -text $title -underline $alt
    return $this
}; # create_note

proc create_cmd {parent title color} {
    #? create button to run O-Saft command; returns widget
    global cfg
    set name [str2obj $title]
    set this $parent.$name
    if {$color < 1 || $color > 4} { set color ""}
    set basecolor [get_color osaft]
    pack [button $this -text $title -bg "$basecolor$color" -command "osaft_exec $parent $title"] -side left
    create_tip   $this "[tip_text start] $title"
    return $this
}; # create_cmd

proc create_win {parent cmd title} {
    #? create window for commands and options
    #  creates one button for each line returned by: o-saft.pl --help=opt|commands
    # title must be string of group of command or options
    global cfg myX
    set this $parent
    set win  $this
    set data $cfg(OPTS)
    if {$cmd eq "CMD"} {
        set data $cfg(CMDS)
    }
        # data is a huge list which contains commands or options grouped by a
        # header line. The window to be created just contains the lines which
        # follow the header line down to the next header line. $skip controls
        # that.

        # we expect following data in $cfg(CMDS):
        #                      Commands for information about this tool
        #    +dump             Dumps internal data for SSL connection and target certificate.
        #    ...
        #                      Commands to check SSL details
        #    +check            Check the SSL connection for security issues.
        #    ...
        #
        # we expect following data in $cfg(OPTS):
        #    OPTIONS
        #    Options for help and documentation
        #    --h
        #    --help
        #    ...
        #    Options for all commands (general)
        #    --no-rc
        #    --dns
        #    ...
        #    Options for SSL tool
        #    --s_client
        #    --no-openssl
        #    --openssl=TOOL
        #    ...

    set skip 1;     # skip data until $title found
    foreach l [split $data "\r\n"] {
        set dat [string trim $l]
        if {[regexp {^(Commands|Options)} $dat]} { set skip 1; };    # next group starts
        if {"$title" eq "$dat"} {   # FIXME: scary comparsion, better use regex
            # title matches: create a window for checkboxes and entries
            set skip 0;
            if {$cfg(VERB)==1} { puts "create_win: $win $dat" }
            set dat [string toupper [string trim $dat ] 0 0]
            set win [create_window $dat ""]
            if {$win eq ""} { return; };    # do nothing, even no: show_window $this;
            set this $win.g
            frame $this;    # frame for grid
            continue
        }
        if {$skip==1}                      { continue; }
        #dbx# puts "DATA $dat"
        ## skipped general
        if {$dat eq ""}                    { continue; }
        if {[regexp {^(==|\*\*)}    $dat]} { continue; }; # header or Warning
        ## skipped commands
        if {[regexp {^\+(cgi|exec)} $dat]} { continue; }; # internal use only
        ## skipped options
       #if {"OPTIONS" eq $dat}             { continue; }
        if {[regexp {^--h$}         $dat]} { continue; }
        if {[regexp {^--help}       $dat]} { continue; }
        if {[regexp {^--(cgi|call)} $dat]} { continue; }; # use other tools for that

        # the line $l looks like:
        #    our_key   some descriptive text
        # where $dat should contain "our_key" and $tip "some descriptive text"
        # so all multiple white spaces are reduced, which results in first word
        # being $dat and all the rest will be $tip
        # multiple white spaces in descriptive text are lost, that's ok if any
        set dat [regsub -all {\s+} $dat { }]
        set tip [regsub {[^\s]+\s*} $dat {}]
        set dat [lindex [split $dat " "] 0]

        if {$cfg(VERB)==1} { puts "create_win: create: $cmd >$dat<" }
        set name [str2obj $dat]
        if {[winfo exists $this.$name]} {
            # this occour if command/or option appears more than once in list
            # hence the warning is visible only in verbose mode
            if {$cfg(VERB)==1} { puts "**WARNING: create_win exists: $this.$name; ignored" }
            continue
        }
        frame $this.$name;              # create frame for command' or options' checkbutton
### pack [button $this.$name.h -text {?} -command "create_help {$dat}" -borderwidth 1] -side left
        if {[regexp {=} $dat]==0} {
            pack [checkbutton $this.$name.c -text $dat -variable cfg($dat)] -side left -anchor w -fill x
        } else {
            regexp {^([^=]*)=(.*)} $l dumm idx val
            pack [label  $this.$name.l -text $idx -width $myX(lenl)]    -side left -anchor w
            pack [entry  $this.$name.e -textvariable cfg($idx)] -fill x -side left -expand 1
            if {[regexp {^[a-z]*$} $l]} { set cfg($idx) $val };   # only set if all lower case
            $this.$name.l config -font TkDefaultFont;   # reset to default as Label is bold
        }
        grid $this.$name -sticky w
        create_tip $this.$name "$tip";  # $tip may be empty, i.e. for options
    }
    pack $this -fill both -expand 1

    # now arrange grid in rows and columns
    # idea: arrange widgets in at least 3 columns
    #       we can use 4 columns in Commands window because widgets are smaller
    set cnt [llength [grid slaves $this]]
    if {$cnt < 1} { return };   # avoid math errors, no need to resize window
    set max 2;          # 3 columns: 0..2
    if {$cmd eq "CMD"} { incr max }; 
    set col 0
    set row 0
    set slaves [lsort -nocase [grid slaves $this]]
    foreach s $slaves {
        if {$col > $max} { incr row; set col 0 }
        #grid config $s -row $row -column $col -padx 8
        incr col
    }
}; # create_win

proc create_buttons {parent cmd} {
    #? create buttons to open window with commands or options
    #  creates one button for header line returned by: o-saft.pl --help=opt|commands
    # cmd must be "OPT" or "CMD" or "TRC"
    global cfg
    set data $cfg(OPTS)
    if {$cmd eq "CMD"} { set data $cfg(CMDS) }
        # expected format of data in $cfg(CMDS) and $cfg(OPTS) see create_win() above

    set txt  [tip_text "tab$cmd"];      # tabCMD and tabOPT
    pack [label  $parent.o$cmd -text $txt ] -fill x -padx 5 -anchor w -side top
    foreach l [split $data "\r\n"] {
        set txt [string trim $l]
        if {[regexp {^(Commands|Options) } $txt]==0} { continue }
            # buttons for Commands and Options only
        if {[regexp {^Options\s*for\s*(help|compatibility) } $txt] != 0} { continue }
            # we do not support these options in the GUI
        ## skipped general
        if {$txt eq ""}                    { continue; }
        if {[regexp {^(==|\*\*)}    $txt]} { continue; }; # header or Warning
        if {"OPTIONS" eq $txt}             { continue; }
        # remove noicy prefix and make first character upper case
        set dat  [string toupper [string trim [regsub {^(Commands|Options) (to|for)} $txt ""]] 0 0]
        set name [str2obj $txt]
        set this $parent.$name
        if {$cfg(VERB)==1} { puts "create_buttons .$name {$txt}" }
        pack [frame $this] -anchor c -padx 10 -pady 2
        pack [button $this.b -text $dat -width 58 -command "create_win .$name $cmd {$txt}" -bg [get_color button] ] \
             [button $this.h -text {?} -command "create_help {$txt}" ] \
        	-side left
        create_tip   $this.b [tip_text settings]

	# argh, some command sections are missing in HELP
        if {[regexp {^Commands to show } $txt]==1} { $this.h config -state disable }
    }
}; # create_buttons

proc osaft_about {mode} {
    #? extract description from myself; returns text
    global arrv argv0
    set fid [open $argv0 r]
    set txt [read $fid]
    set hlp ""
    foreach l [split $txt "\r\n"] {
        if {![regexp {^#[?.]} $l]} { continue; }
        if { [regexp {^#\.}  $l] && $mode eq {ABOUT}} { continue }
        if { [regexp {^\s*$} $l]} { continue }
        set l [regsub -all {\$0} $l $argv0]
        set hlp "$hlp\n[regsub {^#[?.]} $l {}]"
    }
    close $fid
    return $hlp
}; # osaft_about

proc osaft_reset {} {
    #? reset all options in cfg()
    global cfg
    update_status "reset"
    foreach {idx val} [array get cfg] {
        if {[regexp {^[^-]} $idx]}     { continue };# want options only
        if {[string trim $val] eq "0"} { continue };# already ok
        if {[string trim $val] eq "1"} {
            set cfg($idx]) 0
        } else {
            set cfg($idx]) ""
        }
    }
}; # osaft_reset

proc osaft_init {} {
    #? set values from .o-saft.pl in cfg()
    global cfg
    foreach l [split $cfg(.CFG) "\r\n"] {
        if {[regexp "^\s*(#|$)" $l]} { continue }; # skip comments
        if {[regexp {=} $l]} {
            regexp {^([^=]*)=(.*)} $l dumm idx val
            #dbx# puts "K $idx XXX $val"
            set cfg([string trim $idx]) $val
        } else {
            set cfg([string trim $l]) 1
        }
    }
}; # osaft_init

proc osaft_save {type nr} {
    #? save selected output to file; $nr used if $type == TAB
    # type denotes type of data (TAB = tab() or CFG = cfg()); nr denotes entry
    global cfg tab
    if {$type eq "TAB"} {
        set name [tk_getSaveFile -confirmoverwrite true -title "$cfg(TITLE): [tip_text saveto]"     -initialfile "$cfg(SAFT)--$nr.log"]
        if {$name eq ""} { return }
        set fid  [open $name w]
        puts $fid $tab($nr)
    }
    if {$type eq "CFG"} {
        set name [tk_getSaveFile -confirmoverwrite true -title "$cfg(TITLE): [tip_text savetofile]" -initialfile ".$cfg(SAFT)--new"]
        if {$name eq ""} { return }
        set fid  [open $name w]
        foreach {idx val} [array get cfg] { # collect selected options
            if {[regexp {^[^-]} $idx]}     { continue }; # want options only
            if {[string trim $val] eq "0"} { continue };
            if {[string trim $val] eq "1"} {
                puts $fid "$idx"
            } else {
                if {$val ne ""} { puts $fid "$idx=$val" }
            }
        }
    }
    close $fid
    update_status "saved to $name"
}; # osaft_save

proc osaft_exec {parent cmd} {
    #? run $cfg(SAFT) with given command; write result to global $osaft
    global cfg hosts tab
    update_status "$cmd"
    set do  {};     # must be set to avoid tcl error
    set opt {};     # ..
    set targets {}; # ..
    if {$cmd eq "Start"} {
        foreach {idx val} [array get cfg] { # collect selected commands
            if {[regexp {^[^+]} $idx]}     { continue }; # want commands only
            if {[string trim $val] ne "1"} { continue };
            lappend do $idx
        }
    } else {
        set do $cmd
    }
    foreach {idx val} [array get cfg] {     # collect selected options
        if {[regexp {^[^-]} $idx]}  { continue };# want options only
        set val [string trim $val]
        if {$val eq "0"} { continue };      # unset # FIXME: cannot use 0 as value --x=0
        if {$val eq "1"} { lappend opt  $idx; continue };
        if {$val ne  ""} { lappend opt "$idx=$val"; };
    }
    foreach {i h} [array get hosts] {       # collect hosts
        if {$i==0}                  { continue };   # first entry is counter
        if {[string trim $h] eq ""} { continue };   # skip empty entries
        lappend targets $h
    }
    set execme [list exec {*}$cfg(PERL) $cfg(SAFT) {*}$opt {*}$do {*}$targets]; # Tcl >= 8.5
    update_status "$execme"
    incr cfg(EXEC)
    catch {
       #set osaft [eval $execme]; # Tcl < 8.5
        set osaft [{*}$execme];   # Tcl > 8.4
    } exec_msg
    set execme [regsub "^\s*exec\s*" $execme {}];   # pretty print command
    set tab($cfg(EXEC)) "\n$execme\n\n$exec_msg\n"
    set tab_run  [create_note $cfg(objN) "($cfg(EXEC)) $cmd"]
    set txt [create_text  $tab_run $tab($cfg(EXEC))].t ;    # <== ugly hardcoded .t
    pack [button $tab_run.bs -text [btn_text save]     -bg [get_color save]  -command "osaft_save {TAB} $cfg(EXEC)"] -side left
    pack [button $tab_run.bf -text [btn_text filter]                         -command "create_filter $txt $cmd"] -side left
    pack [button $tab_run.bq -text [btn_text closetab] -bg [get_color close] -command "destroy $tab_run"] -side right
    create_tip   $tab_run.bq [tip_text closetab]
    create_tip   $tab_run.bs [tip_text saveto]
    create_tip   $tab_run.bf [tip_text showfilterconfig]
    apply_filter $txt ;        # text placed in pane, now do some markup
    destroy $cfg(winF);        # workaround, see FIXME in create_filtertab
    $cfg(objN) select $tab_run
    update_status "$do done."
}; # osaft_exec

proc copy2clipboard {w shift} {
    #? copy visible text of object to clipboard
    global cfg
    set klasse [winfo class $w]
    set txt {}
    if {$shift==1} { set txt "$w $klasse: " }
    switch $klasse {
       Button       -
       Label        -
       Checkbutton  -
       Radiobutton  { append txt [lindex [$w config -text] 4] }
       Text         { append txt [string trim [$w get 1.0 end]]; }
       Entry        { append txt [string trim [$w get]]; }
       default      { puts "** unbekannte Klasse $klasse" }
    }
    if {$cfg(VERB)==1} { puts "copy2clipboard($w, $shift): $txt" }
    clipboard clear
    clipboard append -type STRING -format STRING -- $txt
}; # copy2clipboard


#_____________________________________________________________________________
#_____________________________________________________________________ main __|

set targets ""
foreach arg $argv {
    switch -glob $arg {
        {--v}   { set cfg(VERB) 1; lappend cfg(FAST) {+quit} {+version}; }
        {--tip} { set cfg(TIP)  1; } # use own tooltip
        {--h}   -
        {--help} { puts [osaft_about "HELP"]; exit; }
        *       { lappend targets $arg; }
        default { puts "**WARNING: unknown parameter '$arg'; ignored" }
    }
}

font create osaftHead   {*}[font config TkFixedFont;]  -weight bold
font create osaftBold   {*}[font config TkDefaultFont] -weight bold
font create osaftSlant  {*}[font config TkDefaultFont] -slant italic
option add *Button.font osaftBold;  # if we want buttons more exposed
option add *Label.font  osaftBold;  # ..
option add *Text.font   TkFixedFont;

# bindings for simply copying text of any widget
foreach klasse [list Button Label Entry Checkbutton Radiobutton Text] {
    bind $klasse  <Control-ButtonPress-1>       { copy2clipboard %W 0 }
    bind $klasse  <Shift-Control-ButtonPress-1> { copy2clipboard %W 1 }
}


## read $cfg(RC) if any
#  this may redefine some previous settings
#  if the file does not exist, the error is silently catched and ignored
set rcfile [file join $env(HOME) $cfg(RC)]
if {[file isfile $rcfile]} { catch { source $rcfile } error_txt }
set rcfile [file join {./}       $cfg(RC)]
if {[file isfile $rcfile]} { catch { source $rcfile } error_txt }

# replace wrong string in cfg_tipp
set cfg_tipp(start) [regsub -all {\$cfg.SAFT.} $cfg_tipp(start) $cfg(SAFT)]

# get information from O-Saft; it's a performance penulty, but simple ;-)
set cfg(HELP)   ""; catch { exec {*}$cfg(PERL) $cfg(SAFT) +help }           cfg(HELP)
if {2 > [llength [split $cfg(HELP) "\n"]]} {
    # exec call failed, probably because PATH does not contain .
    # then cfg(SAFT) returns an error, most likely just on line, like:
    #   couldn't execute "o-saft.pl": no such file or directory
    # as this message depends on the lanuguage setting of the calling shell,
    # we do not check for any string, but for more than on line, means that
    # cfg(HELP) must be more than one line
    set cfg(SAFT) [file join "." $cfg(SAFT)];     # try current directory also
}
set cfg(HELP)   ""; catch { exec {*}$cfg(PERL) $cfg(SAFT) +help }           cfg(HELP)
set cfg(OPTS)   ""; catch { exec {*}$cfg(PERL) $cfg(SAFT) --help=opt }      cfg(OPTS)
set cfg(CMDS)   ""; catch { exec {*}$cfg(PERL) $cfg(SAFT) --help=commands } cfg(CMDS)

if {2 > [llength [split $cfg(HELP) "\n"]]} {
    # failed again, so we have no command and no options also, cant't continue
    tk_messageBox -icon error \
        -message "**ERROR: could not call $cfg(SAFT); exit;\n\n!!Hint: check PATH environment variable."
    exit 2
}


## create toplevel window
wm title        . $cfg(TITLE)
wm iconname     . [string tolower $cfg(TITLE)]
wm geometry     . $myX(geoS)

set w ""
pack [frame $w.ft0]; # create dummy frame to keep create_host() happy

## create command buttons for simple commands and help
pack [frame     $w.fq] -fill x -side bottom
if {$cfg(VERB)==1} {
    pack [button $w.fq.r -text "o"  -command "open \"| $argv0\"; exit" ] -side right
    # TODO: does not work proper 'cause passing --v fails
}
pack [button    $w.fq.bq -text [btn_text quit]  -bg [get_color close] -command {exit}] -side right -padx $myX(rpad)
pack [frame     $w.fc] -fill x
pack [button    $w.fc.bs -text [btn_text start] -bg [get_color start] -command "osaft_exec $w.fc {Start}"] -side left -padx 11
set c 0; # used to change color
foreach b $cfg(FAST) {
    create_cmd $w.fc $b $c;
    if {[regexp {^\+[c]} $b]==0} { incr c };    # command not starting with +c get a new color
}
pack [button    $w.fc.bh -text [btn_text quest] -command "create_help {}"] -side right -padx $myX(padx)
create_tip      $w.fc.bh  [tip_text help]
create_tip      $w.fc.bs "[tip_text start] selected in 'Commands' tab"
create_tip      $w.fq.bq  [tip_text closeme]
set q ::tk::icons::question;    # add a nice icon, if it exists
if {[regexp $q [image names]]} {
    $w.fc.bh config -image $q -width 26 -height 26 -relief flat; # adapt size tologo
}

## create notebook object and set up Ctrl+Tab traversal
set cfg(objN)   $w.note
ttk::notebook   $cfg(objN) -padding 5
ttk::notebook::enableTraversal $cfg(objN)
pack $cfg(objN) -fill both -expand 1

## create TABs: Command and Options
set tab_cmds    [create_note $cfg(objN) "Commands"]
set tab_opts    [create_note $cfg(objN) "Options"]
set tab_filt    [create_note $cfg(objN) "Filter"]
create_buttons  $tab_cmds {CMD}; # fill Commands pane
create_buttons  $tab_opts {OPT}; # fill Options pane
create_filtertab $tab_filt {FIL}; # fill Filter pane

## add Save and Reset button in Options pane
pack [button    $tab_opts.bs -text [btn_text save]  -command {osaft_save "CFG" 0} -bg [get_color start] ] -side left
pack [button    $tab_opts.br -text [btn_text reset] -command {osaft_reset; osaft_init;}                 ] -side left
osaft_init;     # initialise options from .-osaft.pl (values shown in Options tab)
create_tip      $tab_opts.bs [tip_text savetofile]
create_tip      $tab_opts.br [tip_text resetfilterconfig]

## create status line
pack [frame     $w.fl -relief sunken -borderwidth 1] -fill x
pack [text      $w.fl.t -height 2 -relief flat -background [get_color status] ] -fill x
set cfg(objS)   $w.fl.t
$cfg(objS) config -state disabled

## add hosts from command line
foreach host $targets {         # display hosts
    if {$hosts(0) > 5} { puts "**WARNING: only 6 hosts possible; '$host' ignored"; continue };
    create_host $w
    set hosts($hosts(0)) $host
}

## add one Host: line  with  +  and  !  button
create_host $w

## some verbose output
# must be at end when window was created, otherwise wm data is missing or mis-leading
if {$cfg(VERB)==1} {
    puts "PRG $argv0"
    puts "CFG"
    puts " |  browser:   $cfg(browser)"
    puts "TCL version:   $::tcl_patchLevel"
    puts " |  library:   $::tcl_library"
    puts " |  platform:  $::tcl_platform(platform)"
    puts " |  os:        $::tcl_platform(os)"
    puts " |  osVersion: $::tcl_platform(osVersion)"
    puts " |  byteOrder: $::tcl_platform(byteOrder)"
    puts " |  wordSize:  $::tcl_platform(wordSize)"
    puts "TCL rcFileName:$::tcl_rcFileName"
    puts "Tk version:    $::tk_patchLevel"
    puts " |  library:   $::tk_library"
    puts " |  strictMotif: $::tk_strictMotif"
    puts "WM:            [wm frame .]"
    puts " |  geometry:  [wm geometry   .]"
    puts " |  maxsize:   [wm maxsize    .]"
    puts " |  focusmodel:[wm focusmodel .]"
    puts " |  system:    [tk windowingsystem]"; # we believe this a window manager property
    if {[info exists geometry]==1} { puts " |  geometry:  $geometry" }
}

