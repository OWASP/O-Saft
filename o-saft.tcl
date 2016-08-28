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
#?      can be customized in  .o-saft.tcl , which  will be searched for in the
#?      user's  HOME directory  and in the local directory.
#?      Please see  .o-saft.tcl  itself for details. A sample  .o-saft.tcl  is
#?      available in the contrib/ directory.
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
#?      --v     print verbose messages (for debugging)
#?
#? KNOWN PROBLEMS
#?      The markup defined in the filters (see Filter TAB) may not yet produce
#?      perfect layouts for the results and the help texts,  to be improved in
#?      many ways.
#?      Note that the markup is independent of the results and does not change
#?      them, just "highlight" texts of the results.
#?
#?      All  --cfg-*  settings from .o-saft.pl are not handled properly in the
#?      GUI herein.
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
#.      This tools relies on the format of these lines.  If the format changes
#.      commands and options may be missing in the generated GUI.
#.      Following options of  o-saft.pl  are used:
#.          --help  --help=opt  --help=commands
#.      A detailed example of the format can be found in  proc create_win().
#.
#.      The tool will only work if o-saft.pl is available and executes without
#.      errors. All commands and options of  o-saft.pl  will be available from
#.      herein, except:
#.          - all  "--help*"  options (as they make no sense here)
#.          - "+cgi"  and  "+exec"  command (they are for internal use only)
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
#.          cfg_colors()- global variable containing colours for widgets
#.          cfg_texts() - global variable containing texts for widgets
#.          cfg_tips()  - global variable containing texts for tooltips
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
#?      @(#) 1.87 Summer Edition 2016
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

set cfg(SID)    {@(#) o-saft.tcl 1.87 16/08/28 15:17:22 Sommer Edition 2016}
set cfg(TITLE)  {O-Saft}
set cfg(RC)     {.o-saft.tcl}
set cfg(RCmin)  1.7;                    # expected minimal version of cfg(RC)
set cfg(ICH)    [file tail $argv0]
set cfg(ME)     [info script];          # set very early, may be missing later

#-----------------------------------------------------------------------------{
#   this is the only section where we know about o-saft.pl
#   all settings for o-saft.pl go here
set cfg(DESC)   {CONFIGURATION o-saft.pl}
set cfg(SAFT)   {o-saft.pl};            # name of O-Saft executable
set cfg(INIT)   {.o-saft.pl};           # name of O-Saft's startup file
set cfg(.CFG)   {};                     # contains data from cfg(INIT)
                                        # set below and processed in osaft_init
catch {
  set fid [open $cfg(INIT) r]
  set cfg(.CFG) [read $fid];    close $fid; # read .o-saft.pl
}
# some regex to match output from o-saft.pl or data in .o-saft.pl
# mainly used in create_win()
set cfg(rexOPT-cfg)  {^([^=]*)=(.*)};   # match  --cfg-CONF=KEY=VAL
set cfg(rexOUT-head) {^(==|\*\*)};      # match header lines starting with ==
set cfg(rexOUT-int)  {^--(cgi|call)};   # use other tools for that
set cfg(rexCMD-int)  {^\+(cgi|exec)};   # internal use only
#-----------------------------------------------------------------------------}

## configure GUI

variable logo [image create photo -data {
  R0lGODlhGAAYAOMOAAAAAAARAQASAQASAgATAQATAgBwLgCBNgCBNwCCNQCCNgCCNwCDNiZ/AP//
  /////yH5BAEKAA8ALAAAAAAYABgAAASE8MlJq6o4W3W1fwvHfZ6oLKRmfkKLmcnTDlRrv6IEBC0g
  2YXMStf7CWiPnETUqAl8suNylFROilHkanh9GpEME9cInU3EVvJ3gkB3umXppCHGYM2UeuUuP4/V
  WRUJHAcZfEgpgHh5b3teUYsmTV1YBDYCfhwGTlgTA4iSFANQJAccKB8RADs=
}]; # [!] 24x24

set cfg(FAST)   {{+check} {+cipher} {+info} {+quick} {+protocols} {+vulns}}; # quick access commands
set cfg(hist)   "osaft-LNK-T";  # positions in help text
set cfg(curr)   0;              # current position (index) in cfg(help)
set cfg(last)   "";             # search position (index) in cfg(help)
set cfg(see)    "";             # last search index in cfg(help)

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
                                # any ICCCM like: PRIMARY, SECONDARY, CLIPBOARD
                                # or: CUT_BUFFER0 .. CUT_BUFFER7
                                # Hint for X, in particular xterm: .Xresources:
                                #     XTerm*VT100.Translations: #override \
                                #         ... \
                                #         <Btn2Up>: insert-selection(PRIMARY,CLIPBOARD) \
                                #         ... \

set cfg(bstyle) {image};        # button style: {image} or {text}

set my_bg       "[lindex [. config -bg] 4]";  # default background color
                                # this colour is used for buttons too

# define all buttons used in GUI
    # Following table defines the  label text, background colour, image and tip
    # text for each button. Each key (object name) defines one button.
    #
    # This allows to generate the buttons without these attributes (-text, -bg,
    # -image, etc.), which simplifies the code.  These attributes are set later
    # using theme_set(), which then also takes care if there should be a simple
    # theme (just text and background) or a more sexy one using images.
    # Note:   the key (object name) in following table must be the last part of
    #         the object (widget) name of the button, example: .f.about  .

    #----------+---------------+-------+-------+-------------------------------
    # object    button text colour   image      help text (aka tooltip)
    # name      -text       -bg     -image      create_tip()
    #----------+-----------+-------+-----------+-------------------------------
array set cfg_buttons "
    {about}     {{About}    $my_bg  about       {About $cfg(ICH)}}
    {help}      {{?}        $my_bg  ::tk::icons::question  {Open window with complete help}}
    {closeme}   {{Quit}     orange  quit        {Close program}}
    {closewin}  {{Close}    orange  close       {Close window}}
    {closetab} {{Close Tab} orange  closetab    {Close this TAB}}
    {saveresult}  {{Save}   lightgreen save     {Save results to file}}
    {saveconfig}  {{Save}   lightgreen save     {Save configuration to file  }}
    {reset}     {{Reset}    $my_bg  reset       {Reset configuration to defaults}}
    {filter}    {{Filter}   $my_bg  filter      {Show configuration for filtering results}}
    {tkcolor} {{Color Chooser}  $my_bg tkcolor  {Open window to choose a color}}
    {tkfont}  {{Font Chooser}   $my_bg tkfont   {Open window to choose a font}}
    {host_add}  {{+}        $my_bg  host_add    {Add new line for a host}}
    {host_del}  {{-}        $my_bg  host_del    {Remove this line for a host }}
    {help_home} {{^}        $my_bg  help_home   {Go to top of page}}
    {help_prev} {{<}        $my_bg  help_prev   {Go back to previous position}}
    {help_next} {{>}        $my_bg  help_next   {Go forward to next position }}
    {helpsearch}  {{>>}     $my_bg  helpsearch  {Search for text}}
    {cmdstart}  {{Start}    yellow  cmdstart    {Execute $cfg(SAFT) with commands selected in 'Commands' tab}}
    {cmdcheck}  {{+check}   #ffd800 cmdcheck    {Execute $cfg(SAFT) +check   }}
    {cmdcipher} {{+cipher}  #ffd000 cmdcipher   {Execute $cfg(SAFT) +cipher  }}
    {cmdinfo}   {{+info}    #ffc800 cmdinfo     {Execute $cfg(SAFT) +info    }}
    {cmdquit}   {{+quit}    #ffc800 cmdquit     {Execute $cfg(SAFT) +quit (debugging only)}}
    {cmdquick}  {{+quick}   #ffc000 cmdquick    {Execute $cfg(SAFT) +quick   }}
    {cmdprotocols} {{+protocols} #ffb800 cmdproto  {Execute $cfg(SAFT) +protocols }}
    {cmdvulns}  {{+vulns}   #ffb000 cmdvulns    {Execute $cfg(SAFT) +vulns   }}
    {cmdversion} {{+version} #fffa00cmdversion  {Execute $cfg(SAFT) +version }}
";  #----------+-----------+-------+-----------+-------------------------------

    # Note: all buttons as described above,  can be configured also by the user
    # using  cfg(RC).  Configurable are:  text (-text), background colour (-bg)
    # and the tooltip. Because configuering the above table is a bit cumbersome
    # for most users, we provide simple lists with key=value pairs. These lists
    # are:  cfg_colors, cfg_texts and cfg_tips. The settings here are defaults,
    # and may be redifined in cfg(RC) using  cfg_color, cfg_label and cfg_tipp.
    # These lists (arrays in Tcl terms) contain not just the button values, but
    # also values for other objects.  So the lists are initialized here for all
    # other values, and then the values from cfg_buttons are added.

proc buttons_txt  {key} { global cfg_buttons; return [lindex $cfg_buttons($key) 0]; }
proc buttons_bg   {key} { global cfg_buttons; return [lindex $cfg_buttons($key) 1]; }
proc buttons_img  {key} { global cfg_buttons; return [lindex $cfg_buttons($key) 2]; }
proc buttons_tip  {key} { global cfg_buttons; return [lindex $cfg_buttons($key) 3]; }

array set cfg_colors "
    DESC        {-- CONFIGURATION colours used in GUI ------------------------}
    osaft       gold
    button      lightyellow
    code        lightgray
    link        blue
    status      wheat
"

array set cfg_texts "
    DESC        {-- CONFIGURATION texts used in GUI for buttons or labels ----}
    host        {Host\[:Port\]}
    hideline    {Hide complete line}
    c_toggle    {toggle visibility\nof various texts}
"

array set cfg_tips "
    DESC        {-- CONFIGURATION texts used for tool tips on buttons --------}
    settings    {Open window with more settings}
    DESC_other  {-- CONFIGURATION texts used for tool tips on other objects --}
    choosen     {Choosen value for}
    hideline    {Hide complete line instead of pattern only}
    show_hide   {show/hide: }
    tabCMD      {
Select commands. All selected commands will be executed with the 'Start' button.
}
    tabOPT      {
Select and configure options. All options are used for any command button.
}
    tabFILTER   {
Configure filter for text markup: r, e and # specify how the Regex should work;
Forground, Background, Font and u  specify the markup to apply to matched text.
Changes apply to next +command.
}
    DESC_misc   {-- CONFIGURATION texts used in GUI for various other texts --}
    f_key       Key
    f_moder     r
    f_modee     e
    f_chars     {#}
    f_regex     Regex
    f_fg        Foreground
    f_bg        Background
    f_font      Font
    f_u         u
"; # cfg_tips; # Note: text for tab* contain new lines.

# now add default to cfg_* as described before
foreach key [array names cfg_buttons] {
    set cfg_colors($key) [buttons_bg  $key]
    set cfg_texts($key)  [buttons_txt $key]
    set cfg_tips($key)   [buttons_tip $key]
}

proc cfg_update   {} {
    #? legacy conversion of old (pre 1.86) keys from cfg(RC) aka .o-saft.tcl
    #
    # Until version 1.84, respectively 1.6 of cfg(RC), the variables in cfg(RC)
    # were identical to the ones used herein:
    #   cfg_color,  cfg_label, cfg_tipp
    # As cfg(RC) will only be sourced, it needs to have the complete definition
    # of each of these variables, otherwise we may run into some syntax errors.
    # Starting with version 1.86, the variables herein have been renamed to:
    #   cfg_colors, cfg_texts, cfg_tips
    # and also some keys have been renamed.
    # This function copies the settings from cfg(RC) to the internal variables.
    # By doing this, the old keys are converted automatically (see switch cases
    # below).
    # Finally we remove the variables set by cfg(RC).
    #
    putv "()"
    global cfg
    if {[info exists cfg(RCSID)]==1} {
        # cfg(RCSID) is defined in .o-saft.tcl, warn if old one
        _dbx " RCmin$cfg(RCmin) > RCSID$cfg(RCSID) ?"
        if {$cfg(RCmin) > $cfg(RCSID)} {
            tk_messageBox -icon warning -title "$cfg(RC) veriosn $cfg(RCSID)" \
                -message "converting data to new version ...\n\nplease update $cfg(RC) using 'contrib/$cfg(RC)'"
        }
    }
    global cfg_colors cfg_color
    foreach key [array names cfg_color] {
        set value $cfg_color($key)
        # keys used in version < 1.86
        switch -exact $key {
          {start}       { set cfg_colors(cmdstart)  $value }
          {closew}      { set cfg_colors(closewin)  $value }
          {search}      { set cfg_colors(helpsearch) $value }
          {choosecolor} { set cfg_colors(tkcolor)   $value }
          {choosefont}  { set cfg_colors(tkfont)    $value }
          {plus}        { set cfg_colors(host_add)  $value }
          {minus}       { set cfg_colors(host_del)  $value }
          default       { set cfg_colors($key)      $value }
        }
    }
    array unset cfg_color
    global cfg_texts cfg_label
    foreach key [array names cfg_label] {
        set value $cfg_label($key)
        switch -exact $key {
          {start}       { set cfg_texts(cmdstart)   $value }
          {close}       { set cfg_texts(closewin)   $value }
          {search}      { set cfg_texts(helpsearch) $value }
          {color}       { set cfg_texts(tkcolor)    $value }
          {font}        { set cfg_texts(tkfont)     $value }
          {plus}        { set cfg_texts(host_add)   $value }
          {minus}       { set cfg_texts(host_del)   $value }
          default       { set cfg_texts($key)       $value }
        }
    }
    array unset cfg_label
    global cfg_tips cfg_tipp
    foreach key [array names cfg_tipp] {
        set value $cfg_tipp($key)
        switch -exact $key {
          {start}       { set cfg_tips(cmdstart)    $value }
          {closew}      { set cfg_tips(closewin)    $value }
          {showfilterconfig}  { set cfg_tips(filter) $value }
          {resetfilterconfig} { set cfg_tips(reset)  $value }
          {goback}      { set cfg_tips(help_prev)   $value }
          {goforward}   { set cfg_tips(help_next)   $value }
          {search}      { set cfg_tips(helpsearch)  $value }
          {choosecolor} { set cfg_tips(tkcolor)     $value }
          {choosefont}  { set cfg_tips(tkfont)      $value }
          {plus}        { set cfg_tips(host_add)    $value }
          {minus}       { set cfg_tips(host_del)    $value }
          default       { set cfg_tips($key)        $value }
        }
    }
    array unset cfg_tipp
}; # cfg_update

set cfg(PERL)   {};             # full path to perl; empty on *nix

if {[regexp {indows} $tcl_platform(os)]} {
    # Some platforms are too stupid to run our executable cfg(SAFT) directly,
    # they need a proper  perl executable to do it. Check for perl.exe in all
    # directories of the  PATH environment variable. If no executable will be
    # found, ask the user to choose a proper one.
    # There are  no more checks  for the selected file. If it is # wrong, the
    # script will bail out with an error later.
    foreach p [split $env(PATH) ";"] {
        set p [file join $p "perl.exe"]
        if {[file isdirectory $p]} { continue }
        if {[file executable  $p]} {
            set cfg(PERL)     $p
            break
        }
    }
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
set cfg(DEBUG)  0;  # set to 1 to print debugging messages
set cfg(browser) "";            # external browser program, set below

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

proc txt2arr      {str} {
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
  LOW	-regexp	3	red	{}	{}	0	(LOW|low)	word  LOW   anywhere
  WEAK	-exact	4	red	{}	{}	0	WEAK	word  WEAK  anywhere
  weak	-exact	4	red	{}	{}	0	weak	word  weak  anywhere
 MEDIUM	-regexp	6	yellow	{}	{}	0	(MEDIUM|medium)	word MEDIUM anywhere
  HIGH	-regexp	4	_lGreen	{}	{}	0	(HIGH|high)	word  HIGH  anywhere
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

proc putv         {txt} {
    #? verbose output
    global cfg
    if {$cfg(VERB) <= 0} { return; }
    puts stderr "#\[$cfg(ICH)\]:$txt";
}; # putv

proc _dbx         {txt} {
    #? debug output
    global cfg
    if {$cfg(DEBUG) < 1} { return }
    # [lindex [info level 1] 0]; # would be simple, but returns wrong
    # name of procedure if it was call called within []
    # [info frame -1];           # better
    catch { dict get [info frame -1] proc } me; # name of procedure or error
    if {[regexp {not known in dictionary} $me]} { set me "." }; # is toplevel
    puts stderr "#dbx \[$cfg(ICH)\]$me$txt"
}; # _dbx

# if {$cfg(TIP)==1} { # use own tooltip from: http://wiki.tcl.tk/3060?redir=1954

proc tooltip      {w help} {
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

proc create_tip   {w txt} {
    #? add tooltip message to given widget
    global cfg
    if {$cfg(TIP)==1} {     # package tooltip not available, use own one
        tooltip $w "$txt"
    } else {
        set txt [regsub {^-} $txt " -"];# texts starting with - cause problems in tooltip::tooltip
        tooltip::tooltip $w "$txt"
    }
}; # create_tip

proc get_color    {key} {
    #? return color name for key from global cfg_colors variable
    global cfg_colors
    return $cfg_colors($key)
}; # get_color

proc btn_text     {key} {
    #? return text string for key from global cfg_texts variable
    global cfg_texts
    return $cfg_texts($key)
}; # btn_text

proc tip_text     {key} {
    #? return text string for key from global cfg_tips variable
    global cfg_tips
    return $cfg_tips($key)
}; # tip_text

proc get_padx     {key} {
    #? return padx value for key from global myX variable
    global myX
    return $myX($key)
}; # get_padx

proc str2obj      {str} {
    #? convert string to valid Tcl object name; returns new string
    set name [regsub -all {[+]} $str  {Y}];     # commands
    set name [regsub -all {[-]} $name {Z}];     # options (mainly)
    set name [regsub -all {[^a-zA-Z0-9_]} $name {X}];
    set name "o$name";  # first character must be lower case letter
    return $name
}; # str2obj

proc notTOC       {str} {
    #? return 0 if string should be part of TOC; 1 otherwise
    if {[regexp {^ *(NOT YET|WYSIW)} $str]} { return 1; };  # skip some special strings
    if {[regexp {^ *$} $str]}               { return 1; };  # skip empty
    _dbx " no: »$str«";
    return 0
}; # notTOC

proc jumpto_mark  {w txt} {
    #? jump to mark in given text widget, remember mark
    global cfg
    catch { $w see [$w index $txt.first] } err
    if {$err eq ""} {
        # "see" sometimes places text to far on top, so we scroll up one line
        $w yview scroll -1 units
        if {$txt ne "" } {              # store mark in history
            incr cfg(curr)
            if {[llength $cfg(hist)] == $cfg(curr)} {
                lappend cfg(hist) $txt
            } else {
                incr cfg(curr) -1
            }
        }
    } else {
        _dbx  " err: $err"
    }
}; # jumpto_mark

proc jumpto_prev  {w} {
    global cfg
    if {[llength $cfg(hist)] > 0} {
        incr cfg(curr) -1
        jumpto_mark $w [lrange $cfg(hist) $cfg(curr) $cfg(curr)]
    }
}; # jumpto_prev

proc jumpto_next  {w} {
    global cfg
    if {[llength $cfg(hist)] > $cfg(curr)} {
        incr cfg(curr)
        jumpto_mark $w [lrange $cfg(hist) $cfg(curr) $cfg(curr)]
    }
}; # jumpto_next

proc search_highlight {w txt pos} {
    #? remove highlight at pos, search next pos and highlight
    set anf  [$w search -regexp -nocase -count end "$txt" $pos]
    $w tag delete osaft-CURRENT $pos
    $w tag add    osaft-CURRENT $anf "$anf + $end c"
    $w tag config osaft-CURRENT -font osaftBold
}; # search_highlight

proc search_next  {w txt} {
    #? jump to next search text in help window
    global cfg
    _dbx " curr: $cfg(see)"
    $w tag config osaft-CURRENT -font TkFixedFont; # remove highlighting
    set next [lindex [$w tag nextrange osaft-SEARCH $cfg(see)] 1]
    if {$next eq ""} {                  # reached end of range, switch to beginning
        set next [lindex [$w tag ranges osaft-SEARCH] 0]
    }
    if {$next eq ""} { return };        # may happen if nothing matched
    $w see $next
    search_highlight $w $txt $next
    #$w yview scroll 1 units;           # somtimes necessary, but difficult to decide when
    set cfg(see) $next
}; # search_next

proc search_help  {w txt} {
    #? search given text in help window
    global cfg
    if {$txt eq $cfg(last)} { search_next $w $txt; return; }
    set cfg(last) $txt
    $w tag delete osaft-SEARCH;         # get all matches
    set anf [$w search -all -regexp -nocase -count end "$txt" 1.0]
    if {$anf eq ""} { return };         # nothing matched
    set i 0
    foreach a $anf {                    # tag matches
        set e [lindex $end $i];
        incr i
        $w tag add   osaft-SEARCH $a "$a + $e c"
        _dbx " osaft-SEARCH tag:  $a - $a + $e c"
    }
    set tags [$w tag ranges osaft-SEARCH]
    _dbx " osaft-SEARCH tags: $tags"
    set cfg(see)  [lindex $tags 0];     # remember current position
    $w tag config osaft-SEARCH -background black -foreground white
    search_highlight $w $txt $cfg(see)
    $w see $cfg(see)
}; # search_help

proc toggle_cfg   {w opt val} {
    #? use widget config command to change options value
    if {$val ne {}} { $w config $opt $val; }
    return 1
}; # toggle_cfg

proc toggle_txt   {txt tag val line} {
    #? toggle visability of text tagged with name $tag
    # note that complete line is tagged with name $tag.l (see apply_filter)
    global cfg
    _dbx " $txt tag config $tag -elide [expr ! $val]"
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
        _dbx " $key : /$rex/ $mod: bg->$bg, fg->$fg, fn->$fn"
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
        _dbx " $key: $rex F $fg B $bg U $nr font $fn"
        if {$fg ne ""}  { $txt tag config osaft-$key -foreground $fg }
        if {$bg ne ""}  { $txt tag config osaft-$key -background $bg }
        if {$nr ne "0"} { $txt tag config osaft-$key -underline  $nr }
        if {$fn ne ""}  { $txt tag config osaft-$key -font       $fn }
    }
}; # apply_filter

proc www_browser  {url} {
    #? open URL in browser, uses system's native browser
    global cfg
    if {[string length $cfg(browser)] < 1} { puts {**WARNING: no browser found}; return; }
    if {$cfg(VERB)==1} {
        puts  { exec {*}$cfg(browser) $url & }
    }
        catch { exec {*}$cfg(browser) $url & }
}; # www_browser

proc show_window  {w} {
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
    pack [button $w.q -text [btn_text closewin] -command "destroy $w" -bg [get_color closewin]] -side right -padx $myX(rpad)
    create_tip   $w.e "[tip_text choosen] $title"
    create_tip   $w.q [tip_text closewin]
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
    pack [button $this.f1.q -text [btn_text closewin] -bg [get_color closewin] -command "destroy $this"]    -side right -padx $myX(rpad)
    create_tip   $this.f1.q [tip_text closewin]
    if {$title eq "Help" || $title eq {About}} { return $this }
    if {[regexp {^Filter} $title]}             { return $this }

    # all other windows have a header line and a Save button
    pack [frame $this.f0    -borderwidth 1 -relief sunken]     -fill x -side top
    pack [label $this.f0.t  -text $title   -relief flat  ]     -fill x -side left
    pack [button $this.f0.h -text {?} -command "create_help {$title}"] -side right
    pack [button $this.f1.s -text [btn_text saveconfig] \
                  -bg [get_color saveconfig] -command {osaft_save "CFG" 0}]  -side left
    create_tip   $this.f1.s [tip_text saveconfig]
    return $this
}; # create_window

proc create_host  {parent} {
    #?  frame with label and entry for host:port; $nr is index to hosts()
    global cfg hosts myX
    set host  $hosts($hosts(0))
    set leftx 0;    # for nice alignments (we do not use grid)
    incr hosts(0)
    if {$hosts(0)==1}  { set leftx 5 }
    _dbx " host($hosts(0)): $host"
    set this $parent.ft$hosts(0)
          frame  $this
    pack [label  $this.lh -text [btn_text host]]       -side left
    pack [entry  $this.eh -textvariable hosts($hosts(0))]  -side left -fill x -expand 1
    pack [button $this.bp -text [btn_text host_add] -command "create_host {$parent};"] -side left
    pack [button $this.bm -text [btn_text host_del] -command "remove_host $this; set hosts($hosts(0)) {}"] -side left -padx "$leftx $myX(padx)"
    create_tip   $this.bm [tip_text host_del]
    create_tip   $this.bp [tip_text host_add]
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

proc remove_host  {parent} {
    #? destroy frame with label and entry for host:port
    catch {destroy $parent.eh $parent.bp $parent.bm $parent.lh $parent}
}; # remove_host

proc create_text  {parent txt} {
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
    # note: txt must be the index to cfg_texts array, we cannot pass the value
    #       directly because it then must be converted to an object name also,
    #       see next setting of $this
    set this $parent.$txt
    grid [label $this -text [tip_text $txt] -relief raised -borderwidth 1 ] -sticky ew -row 0 -column $col
    create_tip  $this $tip
}; # create_filter_head

proc create_filtertab   {parent cmd} {
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
        _dbx " .$key /$rex/"
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
    pack [button $parent.fc -text [btn_text tkfont]  -command {tk fontchooser show}] -side right
    create_tip   $parent.fc [tip_text tkfont]
    }
    pack [button $parent.cc -text [btn_text tkcolor] -command {create_selected "Color" [tk_chooseColor]} ] -side right
    create_tip   $parent.cc [tip_text tkcolor]
}; # create_filtertab

proc create_filter      {txt cmd} {
    #? create new window with filter commands for exec results; store widget in cfg(winF)
    global cfg f_key f_bg f_fg f_cmt filter_bool myX
    putv "create_filter(»$txt« $cmd)"
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
    _dbx " TXT: $txt | $cmd | $myX(geoF)"
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
        create_tip $this.x$key "[tip_text show_hide] $f_cmt($k)";
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

proc create_help  {sect} {
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
    putv "create_help(»$sect«)"
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

    # add additional buttons
    pack [button $this.f1.h -text [btn_text help_home] -command "jumpto_mark $txt {osaft-LNK-T}"] \
         [button $this.f1.b -text [btn_text help_prev] -command "jumpto_prev $txt"] \
         [button $this.f1.f -text [btn_text help_next] -command "jumpto_next $txt"] \
         [label  $this.f1.l -text " | " ] \
         [entry  $this.f1.e -textvariable cfg(search) ] \
         [button $this.f1.s -text [btn_text helpsearch] -command "search_help $txt \$cfg(search)"] \
        -side left
    pack config  $this.f1.h $this.f1.l -padx $myX(rpad)
    create_tip   $this.f1.h [tip_text help_home]
    create_tip   $this.f1.b [tip_text help_prev]
    create_tip   $this.f1.f [tip_text help_next]
    create_tip   $this.f1.e [tip_text helpsearch]
    create_tip   $this.f1.s [tip_text helpsearch]
         bind    $this.f1.e <Return> "search_help $txt \$cfg(search)"

    # 1. search for section head lines, mark them and add (prefix) to text
    set anf [$txt search -regexp -nolinestop -all -count end {^ {0,5}[A-Z][A-Za-z_? ()=,:.-]+$} 1.0]
    set i 0
    foreach a $anf {
        set e [lindex $end $i];
        set t [$txt get $a "$a + $e c"];# don't trim, we need leading spaces
        set l [string length $t]
        incr i
        _dbx " 1. HEAD: $i\t$t"
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
    # NOTE: used regex must be similar to the one used in 1. above !!
    set anf [$txt search -regexp -nolinestop -all -count end { *[A-Za-z_? ()=,:.-]+( |$)} 3.0 $nam]
    set i 0
    foreach a $anf {
        set e [lindex $end $i];
        set t [$txt get $a "$a + $e c"];
        _dbx " 2. TOC: $i\t$t"
        if {[notTOC $t]} { continue; };                 # skip some special strings
        incr i
        set name [str2obj [string trim $t]]
        set b [$txt search -regexp {[A-Z]+} $a]
        $txt tag add  osaft-TOC    $b "$b + $e c"; # - 1 c";# do not markup leading spaces
        $txt tag add  osaft-TOC-$i $a "$a + $e c";      # but complete line is clickable
        $txt tag bind osaft-TOC-$i <ButtonPress> "jumpto_mark $txt {osaft-HEAD-$name}"
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
    # Now loop over all matches. The difficulty is to distinguish matches,
    # which are the head lines like:
    #   --v
    #   +version
    # and those inside the text, like:
    #   ... option  --v  is used for ...
    # The rules for head lines are:
    #   start with spaces followed by + or - followed by word 'til end of line
    # Anything else is most likely a reference, but there are exceptions like:
    #   --v --v
    # is a head line, and folling might be a reference:
    #   +version.
    # Unfortunately  --v  --v   (and similar examples) will not be detected as
    # head line. This is due to the regex in "text search ...",  which doesn't
    # allo spaces. # FIXME:

    set i 0
    foreach a $anf {
        set e [lindex $end $i];
        set l [$txt get "$a - 2 c" "$a + $e c + 1 c"];  # one char more, so we can detect head line
        set t [string trim [$txt get $a "$a + $e c"]];
        set r [regsub {[+]} $t {\\+}];  # need to escape +
        set r [regsub {[-]} $r {\\-}];  # need to escape -
        set name [str2obj [string trim $t]]
        _dbx " 3. LNK: $i\tosaft-LNK-$name\t$t"
        if {[regexp -lineanchor "\\s\\s+$r$" $l]} {     # FIXME: does not match all lines proper
            # these matches are assumed to be the header lines
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

    # 4. search for all examples and highlight them
    set anf [$txt search -regexp -nolinestop -all -count end "$cfg(SAFT) \[^\\n\]+" 3.0]
    set i 0
    foreach a $anf {
        set e [lindex $end $i];
        set t [$txt get $a "$a + $e c"]
        _dbx " 4. CODE: $i\tosaft-CODE\t$t"
        $txt tag add  osaft-CODE $a "$a + $e c"
        incr i
    }

    # 5. search for all special quoted strings and highlight them
    set anf [$txt search -regexp -nolinestop -all -count end {'[^'\n]+'} 3.0]
    set i 0
    foreach a $anf {
        set e [lindex $end $i];
        set t [$txt get $a "$a + $e c"]
        _dbx " 5. CODE: $i\tosaft-CODE\t$t"
        $txt tag add  osaft-CODE $a "$a + $e c"
        # FIXME: replacing quotes does no work yet
        $txt replace  $a         "$a + 1 c"        { }
        $txt replace "$a + $e c" "$a + $e c + 1 c" { }
        incr i
    }

    # finaly global markups
    $txt tag config   osaft-TOC  -foreground [get_color link]
    $txt tag config   osaft-HEAD -font osaftBold
    $txt tag config   osaft-TOC  -font osaftBold
    $txt tag config   osaft-LNK  -font osaftBold
    $txt tag config   osaft-CODE -background [get_color code]

    _dbx " MARK: [$txt mark names]"
    #_dbx " TAGS: [$txt tag names]"

    set cfg(winH) $this
    if {$sect ne ""} {
        set name [str2obj [string trim $sect]]
        jumpto_mark $cfg(winH).t "osaft-HEAD-$name"
    }
}; # create_help

proc create_note  {parent title} {
    #? create notebook TAB; returns widget
    set name [str2obj $title]
    set this $parent.$name
    set alt  0
    if {[regexp {^\(} $title]} { set alt 1; }; # don't use (, but next charcter
    frame       $this
    $parent add $this   -text $title -underline $alt
    return $this
}; # create_note

proc create_cmd   {parent title color} {
    #? create button to run O-Saft command; returns widget
    global cfg
    set name [str2obj $title]
    set this $parent.$name
    if {$color < 1 || $color > 4} { set color ""}
    set basecolor [get_color osaft]
    pack [button $this -text $title -bg "$basecolor$color" -command "osaft_exec $parent $title"] -side left
    set title [regsub {^\+} $title {cmd}];   # keys start with cmd instead of +
    create_tip   $this "[tip_text $title]"
    return $this
}; # create_cmd

proc create_win   {parent cmd title} {
    #? create window for commands and options
    #  creates one button for each line returned by: o-saft.pl --help=opt|commands
    # title must be string of group of command or options
    putv "create_win($cmd »$title«)"
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
            _dbx " create window: $win »$dat«"
            set dat [string toupper [string trim $dat ] 0 0]
            set win [create_window $dat ""]
            if {$win eq ""} { return; };    # do nothing, even no: show_window $this;
            set this $win.g
            frame $this;    # frame for grid
            continue
        }
        if {$skip==1}                        { continue; }
        #dbx# puts "DATA $dat"
        ## skipped general
        if {$dat eq ""}                      { continue; }
        if {[regexp $cfg(rexOUT-head) $dat]} { continue; }; # ignore header lines
        ## skipped commands
        if {[regexp $cfg(rexCMD-int)  $dat]} { continue; }; # internal use only
        ## skipped options
       #if {"OPTIONS" eq $dat}               { continue; }
        if {[regexp {^--h$}         $dat]}   { continue; }
        if {[regexp {^--help}       $dat]}   { continue; }
        if {[regexp $cfg(rexOUT-int) $dat]}  { continue; }; # use other tools for that

        # the line $l looks like:
        #    our_key   some descriptive text
        # where $dat should contain "our_key" and $tip "some descriptive text"
        # so all multiple white spaces are reduced, which results in first word
        # being $dat and all the rest will be $tip
        # multiple white spaces in descriptive text are lost, that's ok if any
        set dat [regsub -all {\s+} $dat { }]
        set tip [regsub {[^\s]+\s*} $dat {}]
        set dat [lindex [split $dat " "] 0]

        _dbx "create_win: create: $cmd »$dat«"
        set name [str2obj $dat]
        if {[winfo exists $this.$name]} {
            # this occour if command/or option appears more than once in list
            # hence the warning is visible only in verbose mode
            putv "**WARNING: create_win exists: $this.$name; ignored"
            continue
        }
        frame $this.$name;              # create frame for command' or options' checkbutton
### pack [button $this.$name.h -text {?} -command "create_help {$dat}" -borderwidth 1] -side left
        if {[regexp {=} $dat]==0} {
            #dbx# puts "create_win: check: $this.$name.c -variable cfg($dat)"
            pack [checkbutton $this.$name.c -text $dat -variable cfg($dat)] -side left -anchor w -fill x
        } else {
            regexp $cfg(rexOPT-cfg) $l dumm idx val
            #dbx# puts "create_win: entry: $this.$name.e -variable cfg($idx)"
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
        if {$txt eq ""}                      { continue; }
        if {[regexp $cfg(rexOUT-head) $txt]} { continue; }; # header or Warning
        if {"OPTIONS" eq $txt}               { continue; }
        # remove noicy prefix and make first character upper case
        set dat  [string toupper [string trim [regsub {^(Commands|Options) (to|for)} $txt ""]] 0 0]
        set name [str2obj $txt]
        set this $parent.$name
        _dbx " .$name {$txt}"
        pack [frame $this] -anchor c -padx 10 -pady 2
        pack [button $this.b -text $dat -width 58 -command "create_win .$name $cmd {$txt}" -bg [get_color button] ] \
             [button $this.h -text {?} -command "create_help {$txt}" ] \
               -side left
        create_tip   $this.b [tip_text settings]

        # argh, some command sections are missing in HELP
        if {[regexp {^Commands to show } $txt]==1} { $this.h config -state disable }
    }
}; # create_buttons

proc osaft_about  {mode} {
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

proc osaft_reset  {} {
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

proc osaft_init   {} {
    #? set values from .o-saft.pl in cfg()
    global cfg
    foreach l [split $cfg(.CFG) "\r\n"] {
        # expected lines look like:
        #  --no-header
        #  --cfg_cmd=bsi=xxx yyy
        #
        if {[regexp "^\s*(#|$)" $l]} { continue }; # skip comments
        if {[regexp {=} $l]} {
            regexp $cfg(rexOPT-cfg) $l dumm idx val
            # FIXME: there may be multiple  --cfg_cmd=KKK=VVV  settings, but
            #        there is only one variable in the GUU, so last one wins
            set idx [string trim $idx]
        } else {
            set idx [string trim $l]
            set val 1
        }
        _dbx " cfg($idx) = »$val«"
        set cfg($idx) $val
    }
}; # osaft_init

proc osaft_save   {type nr} {
    #? save selected output to file; $nr used if $type == TAB
    # type denotes type of data (TAB = tab() or CFG = cfg()); nr denotes entry
    global cfg tab
    if {$type eq "TAB"} {
        set name [tk_getSaveFile -confirmoverwrite true -title "$cfg(TITLE): [tip_text saveresult]"     -initialfile "$cfg(SAFT)--$nr.log"]
        if {$name eq ""} { return }
        set fid  [open $name w]
        puts $fid $tab($nr)
    }
    if {$type eq "CFG"} {
        set name [tk_getSaveFile -confirmoverwrite true -title "$cfg(TITLE): [tip_text saveconfig]" -initialfile ".$cfg(SAFT)--new"]
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

proc osaft_exec   {parent cmd} {
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
    pack [button $tab_run.bs -text [btn_text saveresult] -bg [get_color saveresult] -command "osaft_save {TAB} $cfg(EXEC)"] -side left
    pack [button $tab_run.bf -text [btn_text filter]                                -command "create_filter $txt $cmd"] -side left
    pack [button $tab_run.bq -text [btn_text closetab]   -bg [get_color closewin]   -command "destroy $tab_run"] -side right
    create_tip   $tab_run.bq [tip_text closetab]
    create_tip   $tab_run.bs [tip_text saveresult]
    create_tip   $tab_run.bf [tip_text filter]
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
       default      { puts "** unknownclass $klasse" }
    }
    putv "copy2clipboard($w, $shift): {\n $txt\n#}"
    clipboard clear
    clipboard append -type STRING -format STRING -- $txt
}; # copy2clipboard


#_____________________________________________________________________________
#_____________________________________________________________________ main __|

set targets ""
foreach arg $argv {
    switch -glob $arg {
        {--dbx} -
        {--d}   { set cfg(DEBUG) 1; }
        {--v}   { set cfg(VERB)  1; lappend cfg(FAST) {+quit} {+version}; }
        {--tip} { set cfg(TIP)   1; }  # use own tooltip
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

#   search browser, first matching will be used
set __native    "";
# next switch is ugly workaround to detect special start methods ...
switch [tk windowingsystem] {
    "aqua"  { set __native "open"  }
    "Aqua"  { set __native "open"  }
    "win32" { set __native "start" }
    "win64" { set __native "start" }
}
foreach b " $__native \
            firefox chrome chromium iceweasel konqueror mozilla \
            netscape opera safari webkit htmlview www-browser w3m \
          " {
    set binary [lindex [auto_execok $b] 0]; # search in $PATH
    _dbx " browser: $b $binary"
    if {[string length $binary]} {
        set cfg(browser) $binary
        break
    }
}

## read $cfg(RC) if any
#  if the file does not exist, the error is silently catched and ignored
set rcfile [file join $env(HOME) $cfg(RC)]
if {[file isfile $rcfile]} { catch { source $rcfile } error_txt }
set rcfile [file join {./}       $cfg(RC)]
if {[file isfile $rcfile]} { catch { source $rcfile } error_txt }
cfg_update;                     # update configuration as needed

# get information from O-Saft; it's a performance penulty, but simple ;-)
set cfg(HELP)   ""; catch { exec {*}$cfg(PERL) $cfg(SAFT) +help }           cfg(HELP)
if {2 > [llength [split $cfg(HELP) "\n"]]} {
    # exec call failed, probably because PATH does not contain . then cfg(SAFT)
    # returns an error, most likely just one line, like:
    #   couldn't execute "o-saft.pl": no such file or directory
    # as this message depends on the lanuguage setting of the calling shell, we
    # do not check for any specific string,  but for more than one line,  means
    # that cfg(HELP) must be more than one line
    set cfg(SAFT) [file join "." $cfg(SAFT)];     # try current directory also
}
set cfg(HELP)   ""; catch { exec {*}$cfg(PERL) $cfg(SAFT) +help }           cfg(HELP)
set cfg(OPTS)   ""; catch { exec {*}$cfg(PERL) $cfg(SAFT) --help=opt }      cfg(OPTS)
set cfg(CMDS)   ""; catch { exec {*}$cfg(PERL) $cfg(SAFT) --help=commands } cfg(CMDS)

if {2 > [llength [split $cfg(HELP) "\n"]]} {
    # failed again, so we have no command and no options also, can't continue
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
pack [button    $w.fq.bq -text [btn_text closeme]  -bg [get_color closeme]  -command {exit}] -side right -padx $myX(rpad)
pack [frame     $w.fc] -fill x
pack [button    $w.fc.bs -text [btn_text cmdstart] -bg [get_color cmdstart] -command "osaft_exec $w.fc {Start}"] -side left -padx 11
set c 0; # used to change color
foreach b $cfg(FAST) {
    create_cmd $w.fc $b $c;
    if {[regexp {^\+[c]} $b]==0} { incr c };    # command not starting with +c get a new color
}
pack [button    $w.fc.bh -text [btn_text help] -command "create_help {}"] -side right -padx $myX(padx)
create_tip      $w.fc.bh  [tip_text help]
create_tip      $w.fc.bs  [tip_text cmdstart]
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
pack [button    $tab_opts.bs -text [btn_text saveresult] -command {osaft_save "CFG" 0} -bg [get_color cmdstart] ] -side left
pack [button    $tab_opts.br -text [btn_text reset]      -command {osaft_reset; osaft_init;}                 ] -side left
osaft_init;     # initialise options from .-osaft.pl (values shown in Options tab)
create_tip      $tab_opts.bs [tip_text saveconfig]
create_tip      $tab_opts.br [tip_text reset]

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

_dbx " hosts: $hosts(0)"

## some verbose output
# must be at end when window was created, otherwise wm data is missing or mis-leading
if {$cfg(VERB)==1 || $cfg(DEBUG)==1} {
    # cfg(RCSID) set in RC-file
    set rc  "not found"; if {[info exists cfg(RCSID)]==1} { set rc  "found" };
    set ini "not found"; if {$cfg(.CFG) ne ""}            { set ini "found" };
    set tip "not used";  if {$cfg(TIP)  == 0 }            { set tip "used" };
    set geo "";          if {[info exists geometry]==1}   { set geo "$geometry" }
   #.CFG:      $cfg(.CFG)   # don't print, too much data

    puts "
PRG $argv0  -- $cfg(ICH)
 |  RC:        $cfg(RC)\t$rc
 |  INIT:      $cfg(INIT)\t$ini
CFG
 |  TITLE:     $cfg(TITLE)
 |  browser:   $cfg(browser)
 |  tooltip:   tooltip package\t$tip
 |  bstyle:    $cfg(bstyle)
 |  PERL:      $cfg(PERL)
 |  SAFT:      $cfg(SAFT)
TCL version:   $::tcl_patchLevel
 |  library:   $::tcl_library
 |  platform:  $::tcl_platform(platform)
 |  os:        $::tcl_platform(os)
 |  osVersion: $::tcl_platform(osVersion)
 |  byteOrder: $::tcl_platform(byteOrder)
 |  wordSize:  $::tcl_platform(wordSize)
 |  rcFileName:$::tcl_rcFileName
Tk  version:   $::tk_patchLevel
 |  library:   $::tk_library
 |  strictMotif: $::tk_strictMotif
WM  :          [wm frame      .]
 |  geometry:  [wm geometry   .]
 |  maxsize:   [wm maxsize    .]
 |  focusmodel:[wm focusmodel .]
 |  system:    [tk windowingsystem]
 |  geometry:  $geo
_/"
    #          [tk windowingsystem] # we believe this a window manager property
}

