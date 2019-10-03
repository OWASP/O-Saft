#!/bin/sh
#| restarts using wish \
exec wish "$0" ${1+"$@"}

#!#############################################################################
#!#             Copyright (c) 2019, Achim Hoffmann, sic[!]sec GmbH
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
#?      $0 [OPTIONS] [host:port] [host:port] ...
#?      $0 [OPTIONS] --load=result-from-o-saft.pl-file
#?      $0 [OPTIONS] [+commands] [host:port] [host:port] ...
#?
#? DESCRIPTION
#?      This is a simple GUI for  O-Saft - OWASP SSL advanced forensic tool.
#?      The GUI supports all commands (Commands TAB) and options (Options TAB)
#?      available in  o-saft.pl. For each command  o-saft.pl  will be executed
#?      as specified. Results are printed in a new TAB of the GUI. A filter to
#?      markup some important texts is applied to the results in the GUI. This
#?      filter can be modified and extended in the  Filter TAB.
#?      All results and settings (commands and options) can be saved to files.
#?
#?      Can be used to read saved results from other calls of o-saft.pl.
#?
#?      Any argument starting with  +  are condidered a command for  o-saft.pl
#?      and  o-saft.pl  will be started with all other  options,  commands and
#?      targets and show the results in the GUI.
#?
#?   Result TAB
#?      The result of  o-saft.pl  are shown in a new TAB.  The format (layout)
#?      of the result can be simple "text" or "table".  This can be configured
#?      in the  Options TAB.
#?
#?      The difference between the formats are:
#?      "table"
#?        The table consist of 4 columns: Nr, Label, Value and Comment. It can
#?        be sorted according each. All Filters are applied to matching lines.
#?        The  Filter  will hide the lines completely.
#?        Saving the results will only save the visible lines. These lines are
#?        saved in the order of the last sorting.
#?        Some informational lines and all header lines (see  --header option)
#?        from  o-saft.pl  are not shown and will not be saved.
#?      "text"
#?        In this format, the results are shown in the same format as returned
#?        by  o-saft.pl. Lines cannot be sorted. The Filter is applied to each
#?        matching line. The  Filter  will just remove the text,  but not hide
#?        the lines.
#?        Saving the result will save the complete text.
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
#?     Buttons
#?      By default, an image will be used for  most buttons.  Images look more
#?      modern than the standard Tcl/Tk buttons. Tcl/Tk does not support round
#?      edges, images as background, or different look for activated buttons.
#?      The images are read from a separate file: o-saft-img.tcl . If the file
#?      is missing, no images will be used, but the simple texts.
#?      For each button an image can be specified in o-saft-img.tcl , example:
#?          set IMG(my-file) [image create photo -file path/to/your-file ]
#?          set cfg_images(+info)  {my-file};   # where +info is your command
#?
#?   Copy Texts
#?      All texts visible in the GUI,  wether a label, a button, an entry or a
#?      text itself, can be copied to the systems clipboard, using the systems
#?      standard copy&paste methods, or with:
#?         <Control-ButtonPress-1>
#?      For debugging  <Shift-Control-ButtonPress-1>   will prefix the text by
#?      the pathname and the class of the object containing the text.
#?      Keep in mind that it also copies the huge text in the help window.
#?      With  <Control-ButtonPress-1>  or  <Shift-Control-ButtonPress-1>   the
#?      text will be copied to the (ICCCM) buffer CLIPBOARD. This ensures that
#?      it will not interfere with the usual copy&paste buffer  PRIMARY.
#?      <ButtonPress-1> is the "select button", usually the left mouse button.
#?      On X.org systems, the  CLIPBOARD  can be pasted using the context menu
#?      (which is most likely the <left click>).
#?
#?   Help / Search
#?      The help [?] button opens a new window with the complete documentation
#?      of O-Saft (in particular the result of: o-saft.pl +help ).
#?      The documentation contains clickable links (in blue) to other sections
#?      in the text. Patterns may be specified to be searched for in the text.
#?      All texts matching the pattern are highligted.
#?      Search can be done forward and backward to the current positions,  see
#?      the  [<]  and  [>]  buttons at bottom of the window. Going to the next
#?      or previous search result will then  highlight the  complete paragraph
#?      containing the matched text.
#?
#?      When more than 5 matches are found,  an additional window will display
#?      all matches as an overview. Click on a highligted match in this window
#?      will show the paragraph containing the match in the help window.
#?      When multiple "overview" windows are open, each handles its matches.
#?
#?      The search pattern can be used in following modes:
#?        exact - use pattern as literal text
#?        regex - use pattern as regular expression (proper syntax required)
#?        smart - convert pattern to regex: each character may be optional
#?        fuzzy - convert pattern to regex: each position may be optional
#?      Example:
#?        exact:  (adh|dha) - search for literal text  (adh|dha)
#?        regex:  (adh|dha) - search for word  adh  or  word  dha
#?        regex:  her.*list - search for text  her  followed by  list
#?        regex:  (and      - fails, because of syntax error
#?        smart:  and       - search for  and  or  a?nd  or  an?d  or  and?
#?        fuzzy:  and       - search for  and  or  .?nd  or  a.?d  or  an.?
#?
#?      Note: regex are applied to lines only, pattern cannot span more than a
#?            single line.
#?      The pattern must have at least 4 characters, except for mode "exact".
#?
#?      The GUI contains various [?] buttons. Clicking such a button will show
#?      the corresponding section in the help window  context sensitive).
#?
#? OPTIONS
#?      --h     print this text
#?      --help=opts print options ((for compatibility with o-saft.pl)
#?      --v     print verbose messages (calling external tools)
#?      --d     print more verbose messages (for debugging)
#?      --d=D   print debug messages according level
#?              D=1     - print verbose messages (main)
#?              D=2     - print proc calls (those not triggerd by events)
#?              D=4     - print debugging in proc
#?              D=8     - print verbose debugging for "help" window
#?              values can combined, like --d=6 for print procs and data there
#?              all  --d=*  imply  --v
#?      --rc    print template for .o-saft.tcl
#?      --text  use simple texts as labels for buttons
#?      --img   use images as defined in o-saft-img.tcl for buttons
#?              (not recommended on Mac OS X, because Aqua has nice buttons)
#.      --tip   use own tooltip
#.      --trace use Tcl's trace to trace proc calls
#?      --load=FILE read FILE and show in result TAB
#?      --id=ID     use Docker image ID (registry:tag); default: owasp/o-saft
#?      --tag=TAG   use Docker image ID with tag; default: (empty)
#?      --docker    use o-saft-docker instead of o-saft.pl
#.      --gui       dummy for compatibility with other tools
#?      --version   print version number
#.      +VERSION    print version number (for compatibility with o-saft.pl)
#.      +quit       exit without GUI (for compatibility with o-saft.pl)
#.      --test-osaft    - just print text used for help window (help button)
#?
#? DOCKER
#?      This script can be used from within any Docker image. The host is then
#?      responsible for providing the proper protocols for the GUI (i.e. X11).
#?      In this case,  anything is executed inside the Docker image,  just the
#?      graphical output is passed to the host. This mode is started with
#?          o-saft-docker gui
#?      which does the necessary magic with Docker for protocol and DISPLAY.
#?
#?      When used with the  --docker  option, this script runs on the host and
#?      connects to an O-Saft Docker image to execute o-saft.pl there with all
#?      the selected commands and options.
#?      In this mode,  o-saft-docker  will be used instead of o-saft.pl, which
#?      must be available on the host.
#?      Note that  o-saft-docker  relies on O-Saft's Docker image osawp/o-saft
#?      which has its own (Docker) entrypoint.  This means that  o-saft-docker
#?      is responsible to provide the same functionality as  o-saft.pl  does.
#?      Adaptions, if necessary, should be done in  o-saft-docker.
#?
#?      Summary
#?          o-saft.tcl --docker     - run on host using o-saft.pl in Docker
#?          o-saft-docker gui       - run in Docker with display to host
#?
#? KNOWN PROBLEMS
#?      Using option  -v  causes a Tcl error, like:
#?         application-specific initialization failed: "-v" option requires an\
#?         additional argument
#?      This is a Tcl problem and cannot be fixed herein.
#?
#?      The markup defined in the filters (see Filter TAB) may not yet produce
#?      perfect layouts for the results and the help texts,  to be improved in
#?      many ways.
#?      Note that the markup is independent of the results and does not change
#?      them, just "highlight" texts of the results.
#?
#?      All  --cfg-*  settings from .o-saft.pl are not handled properly in the
#?      GUI herein.
#?
#?      The busy cursor does not work on Win32 and Win64 systems.
#?
#?      Selected coloured text will not be highlighted. Anyway it is selected.
#?
#?      Some Tk widgets seem to have limits. This may result in errors like:
#?          X Error of failed request:  BadAlloc (insufficient resources for operation)
#?      There exist configurations as workaround to avoid such errors, see:
#?          cfg(max53)
#?
#? ARGUMENTS
#?      All arguments,  except the options described above,  are treated  as a
#?      hostname to be checked.
#?
#? SEE ALSO
#?      o-saft.pl
#?      o-saft-docker
#?
#. LAYOUT
#.           +---------------------------------------------------------------+
#.       (H) | Host:Port [________________________________________]  [+] [-] |
#.           |                                                           [!] |
#.       (C) | [Start] [+info] [+check] [+cipher] [+quick] [+vulns]      [?] |
#.       (O) | [ ] --header  [ ] --enabled  [ ] --no-dns  [ ] -no-http  ...  |
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
#.       (O) - CheckButtons for most commonly used options
#.       (T) - Frame containing panes for commands, options, filter, results.
#.       (S) - Frame containing Status messages
#.       [+] - Add line with Host:Port
#.       [-] - Remove line with Host:Port
#.       [!] - Help about  $0
#.       [?] - Help about  o-saft.pl
#.
#.      Filter TAB Description
#.           +---------------------------------------------------------------+
#.       (f) |    Key     r  e  #  RegEx  Foreground Background  Font     u  |
#.           | +---------+--+--+--+------+----------+----------+--------+--- |
#.       (F) | |== CMT    *  o  0  ^==*               gray      osaftHead x  |
#.           | +---------+--+--+--+------+----------+----------+--------+--- |
#.           | ...                                                           |
#.           +---------------------------------------------------------------+
#.
#.       (f) - Headline for filter description
#.             key        - unique key for this filter
#.             r          - RegEx used as regular expression
#.             e          - RegEx used as exact match
#.             #          - Nr. of characters to be matched by RegEx
#.             Foreground - colour for matched text
#.             Background - colour for background of matched text
#.             Font       - use this font for matched text
#.             u          - matched text will be underlined
#.       (F) - Filter settings
#.             example of a filter
#.
#. LIMITATIONS
#.
#. HACKER's INFO
#.   TODO (7/2017):
#.      - "docker status" button is a quick&dirty hack
#.   TODO (8/2016):
#.      - need to check if ugly hacks for Aqua (Mac OS X 10.6  with  Tk 8.5.7)
#.        are still necessary on modern Macs, in particular:
#.        * tk_getSaveFile -confirmoverwrite
#.        * package require Img
#.
#.   Data Used to Build GUI
#.      Generation of all objects (widgets in Tk slang) is done  based on data
#.      provided by  o-saft.pl  itself, in praticular some  --help=*  options,
#.      see  CONFIGURATION o-saft.pl  below. Output of all  --help=*  must  be
#.      one item per line, like:
#.          This is a label, grouping next lines
#.          +command1   Command nr 1
#.          +command2   Command nr 2
#.          Options for commands
#.          --opt1      this options does something
#.      This tools relies on the format of these lines. If the format changes,
#.      commands and options may be missing in the generated GUI.
#.      Following options of  o-saft.pl  are used:
#.          --help  --help=opt  --help=commands
#.      A detailed example of the format can be found in  proc create_win().
#.      The functions  create_win() and create_buttons()  mainly use the RegEx
#.      prg(rec*)  defined in the  CONFIGURATION  (see below) to  match output
#.      from o-saft.pl . The code in these functions may be used to parse data
#.      from other tools too.
#.
#.      When building the complete documention (help window),  additional text
#.      documentation (beside that provided by +help) will be added before the
#.      ATTRIBUTION  section.  Hence ATTRIBUTION must exist as  section header
#.      in output of "o-saft.pl +help".
#.
#.      The tool will only work if o-saft.pl is available and executes without
#.      errors. All commands and options of  o-saft.pl  will be available from
#.      herein, except:
#.          - all  "--help*"  options (as they make no sense here)
#.          - "+cgi"  and  "+exec"  command (they are for internal use only)
#.
#.   Some Nameing Conventions
#.       - procedures:
#.          create_*    - create widget or window
#.          osaft_*     - run external  o-saft.pl  (and process output)
#.          search_*    - searching texts in help (widget in help window)
#.       - variables (GUI):
#.          HELP-       - prefix used for all Tcl-text tags in help
#.          f_*         - prefix used for all filter list variables
#.          txt         - a text widget
#.          w  or  obj  - any widget
#.          parent      - parent widget (may be toplevel)
#.          cfg()       - global variable containing most configurations
#.          cfg_colors()- global variable containing colours for widgets
#.          cfg_texts() - global variable containing texts for widgets
#.          cfg_tipps() - global variable containing texts for tooltips
#.          search()    - global variable containing texts used for searching
#.          myX()       - global variable for windows and window manager
#.       - variables (O-Saft execution):
#.          hosts()     - global variable with list of hosts to be checked
#.          results()   - global variable containing results of executions
#.       - comments
#.          lines starting with  #.
#.                      - these lines are intended for internal documentation
#.          lines starting with  #?
#.                      - these lines are intended for public documentation
#.          lines starting with  #?  (inside proc definition)
#.                      - lines are used for internal developer documentation
#.          lines starting with  #|
#.                      - lines are used for internal developer documentation
#.          lines with  ;#
#.                      - Tcl requires a  ;  after the statement before any
#.                        comment; the  ; is usually right before the  #
#.
#.   Codeing (general)
#.      Sequence of function definitions done to avoid forward declarations.
#.      See  Debugging Options  below also.
#.
#.   Codeing (GUI)
#.      Images (i.e.for buttons) are defined in  o-saft-img.tcl, which must be
#.      installed in same path as  o-saft.tcl  itself.  The definitions are in
#.      a separate file to keep the code more clean herein.
#.
#.      All buttons for the GUI are defined in a tabular array,  where the key
#.      is used as part of the object name. For details please see comments at
#.          # define all buttons used in GUI
#.      Note that the button texts defined there are displayed  when using our
#.      own "Copy Text" (see above) with <Control-ButtonPress-1>,  even if the
#.      button is displayed as image.
#.
#.   Traceing (GUI)
#.      Tcl's  trace  functionality is used to trace most procs defined herein
#.      and all created buttons.  See trace_commands() and trace_buttons() for
#.      details. Tracing does not yet work for buttons created in sub-windows.
#.      Traceing is invoked with  --trace  option.
#.
#.   Traceing (program flow)
#.      --d=X         - see description above
#.
#.   Traceing and Debugging
#.      All output for --trace and/or --dbx is printed on STDERR.
#.      Trace messages are prefixed with:   #[$0]:
#.      Debug messages are prefixed with:   #dbx [$0]:
#.
#.   Notes About Tcl/Tk
#.      We try to avoid platform-specific code. The only exceptions (2015) are
#.      the perl executable and the start method of the external browser.
#.      Another exception (8/2016) is "package require Img" which is necessary
#.      on some Mac OS X.
#.      All external programs are started using Tcl's  {*}  syntax.
#.      If there is any text visible, we want to copy&paste it. Therefore most
#.      texts are placed in Tk's text widget instead of a label widget, 'cause
#.      text widgets allow selecting their content by default, while labels do
#.      not. These text widgets are set to state "read-only"  instaed of Tcl's
#.      disabled state, see gui_set_readonly() for details.
#.
#.      This is no academically perfect code, but quick&dirty scripted:
#.       - makes use of global variables instead of passing parameters etc..
#.       - mixes layout and functions and application logic
#.       - some widget names are hardcoded
#.
#? VERSION
#?      @(#) 1.226 Summer Edition 2019
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
#___________________________________________________________ early bindings __|

# Bindings for simply copying text of any widget.
# To avoid conflicts with other common bindings, we use Ctrl + click to copy
# the text.  Unfortunately this does not allow to select texts individually,
# but only as a whole.
# Bindings need to be done very early, so that they are active when Tcl/Tk's
# wish uses dialogs (i.e. tk_messagebox). The called function copy2clipboard
# might be defined later in the code, but it must be done before any usage.
# Hence it's defined right below.

foreach klasse [list  Button  Combobox  Entry  Label  Text Message Spinbox \
                     TButton TCombobox TEntry TLabel TText Frame Menu \
                     LabelFrame  PanedWindow Scale Scrollbar \
                     Checkbutton Menubutton  Radiobutton Dialog] {
    bind $klasse  <Control-ButtonPress-1>       { copy2clipboard %W 0 }
    bind $klasse  <Shift-Control-ButtonPress-1> { copy2clipboard %W 1 }

}

proc copy2clipboard {w shift} {
    #? copy visible text of object to clipboard
    global cfg
    set klasse [winfo class $w]
    set txt {}
    if {$shift==1} { set txt "$w $klasse: " }
    # TODO: Spinbox not complete; some classes are missing
    switch $klasse {
       Frame        { append dum "nothing to see in frames" }
       Button       -
       Combobox     -
       Dialog       -
       Label        -
       Spinbox      -
       TButton      -
       TCombobox    -
       TLabel       -
       Checkbutton  -
       Radiobutton  { append txt [lindex [$w config -text] 4] }
       Entry        -
       TEntry       { append txt [string trim [$w get]]; }
       Text         -
       TText        { append txt [string trim [$w get 1.0 end]]; }
       default      { puts "** unknown class $klasse" }
    }
    putv "copy2clipboard($w, $shift): {\n $txt\n#}"
    clipboard clear
    clipboard append -type STRING -format STRING -- $txt
}; # copy2clipboard

#_____________________________________________________________________________
#____________________________________________________________ configuration __|

if {![info exists argv0]} { set argv0 "o-saft.tcl" };   # if it is a tclet

set cfg(SID)    "@(#) o-saft.tcl 1.226 19/10/03 10:14:32"
set cfg(mySID)  "$cfg(SID) Spring Edition 2019"
                 # contribution to SCCS's "what" to avoid additional characters
set cfg(VERSION) {1.226}
set cfg(TITLE)  {O-Saft}
set cfg(RC)     {.o-saft.tcl}
set cfg(RCmin)  1.13                   ;# expected minimal version of cfg(RC)
set cfg(ICH)    [file tail $argv0]
set cfg(DIR)    [file dirname $argv0]  ;# directory of cfg(ICH)
set cfg(ME)     [info script]          ;# set very early, may be missing later
set cfg(IMG)    {o-saft-img.tcl}       ;# where to find image data
                                        # O-Saft means built-in
set cfg(HELP)   ""                     ;# O-Saft's complete help text
set cfg(files)  {}                     ;# files to be loaded at startup --load
set cfg(.CFG)   {}                     ;# contains data from prg(INIT)
                                       ;# set below and processed in osaft_init
set cfg(quit)   0                      ;# quit without GUI
#et cfg(HELP-key) ""                   ;# contains linenumber of result table

#-----------------------------------------------------------------------------{
#   Definitions outside RC-ANF - RC-END scope, because they're not intended to
#   be changed in .o-saft.tcl .
#
#   define some regex to match output from o-saft.pl or data in .o-saft.pl
#   mainly used in create_win() and create_buttons()
set prg(DESC)   {-- CONFIGURATION regex to match output from o-saft.pl -------}
set prg(rexCMD-int)  {^\+(cgi|exec)}   ;# internal use only
set prg(rexOPT-cfg)  {^([^=]*)=(.*)}   ;# match  --cfg-CONF=KEY=VAL
set prg(rexOPT-help) {^--(h$|help)}    ;# match  --h  ot  --help
set prg(rexOUT-head) {^(==|\*\*)}      ;# match header lines starting with ==
set prg(rexOUT-int)  {^--(cgi|call)}   ;# use other tools for that
set prg(rexOUT-cmd)  {^(Commands|Options)} ;# match header lines for --help=cmd
set prg(rexOUT-hide) {^Options\s*for\s*(help|compatibility) }  ;# match groups not shown here
set prg(rexOUT-show) {^Commands to show }  ;# commands without explizit HELP section

#set _me [regsub -all {^[./]*} $prg(SAFT) {}]   ;# remove ./ but prg(SAFT) later
    # causes problems in regsub on Mac OS X if $prg(SAFT) starts with ./
set prg(rexCOMMANDS) "\(o-saft\(.pl|.tcl|-docker\)?|checkAllCiphers.pl|\(/usr/local/\)?openssl|docker|mkdir|ldd|ln|perlapp|perl2exe|pp\)"
    # most common tools used in help text...
set prg(post)   {}             ;# --post=  parameter, if passed on command line
set prg(option) 0  ;# set to 1 to avoid internal "option add ..." commands
#-----------------------------------------------------------------------------}

# RC-ANF {

#-----------------------------------------------------------------------------{
#   This is the only section where we know about  o-saft.pl , all settings for
#   o-saft.pl go here.
set prg(DESC)   {-- CONFIGURATION o-saft.pl ----------------------------------}
set prg(INIT)        {.o-saft.pl}      ;# name of O-Saft's startup file
set prg(SAFT)        {o-saft.pl}       ;# name of O-Saft executable
    # Will be set to  o-saft-docker  when  --docker is given
    # prg(SAFT) must be found with the system's PATH environment variable,
    # otherwise a full path must be used here.
#-----------------------------------------------------------------------------}

set prg(DESC)   {-- CONFIGURATION external programs --------------------------}
set prg(PERL)       {}                 ;# full path to perl; empty on *nix
set prg(BROWSER)    ""                 ;# external browser program, set below
    # o-saft.tcl tries to find the browser automatically, a list of well known
    # browser names is used for that. Another browser can be set here, must be
    # a full path or found with PATH environment variable.
set prg(TKPOD)      {O-Saft}           ;# name of external viewer executable
    # o-saft.tcl uses built-in functionality to show its  documentation.  This
    # documentation is available in POD format also: o-saft.pod.
    # If this variable is set to the name of an external program, this program
    # will be used to show the documentation.  It is recommended to use a full
    # path to the program.
    # Possible values, beside others, are:
    #    O-Saft     - reserved for o-saft.tcl's built-in vierwer
    #    tkpod      - Tcl/Tk-based viewer
    #    podviewer  - GTK-based viewer
    # Advantage of external viewers:
    #    tkpod      + much better search capabilities
    # Disadvantage of external viewers:
    #    tkpod      - context-sensitive help used by o-saft.tcl not possible
    #    podviewer  - context-sensitive help used by o-saft.tcl not possible
    #    *          - all viewers must be started in background and will not
    #                 be closed with o-saft.tcl itself

set prg(docker-id)  {owasp/o-saft}     ;# Docker image ID, if needed
set prg(docker-tag) {latest}           ;# Docker image tag, if needed

set prg(DESC)   {-- CONFIGURATION default buttons and checkboxes -------------}
set prg(Ocmd)   {{+check} {+cipher} {+info} {+quick} {+protocols} {+vulns}};
    # List of quick access commands, for which a button will be created in the
    # GUI. This must be commands of o-saft.pl, which start with  +  character.
set prg(Oopt)   {{--header} {--enabled} {--no-dns} {--no-http} {--no-sni} {--no-sslv2} {--no-tlsv13}};
    # List of quick access options,  for which a button will be created in the
    # GUI. This must be options of o-saft.pl, which start with  --  character.

set myX(DESC)   {-- CONFIGURATION window manager geometry --------------------}
#   set minimal window sizes to be usable in a 1024x768 screen
#   windows will be larger if the screen supports it (we rely on "wm maxsize")
set myX(geoo)   "660x720"      ;# geometry of Help window

set myX(geoO) "$myX(geoo)-0+0" ;# geometry and position of Help      window
set myX(geo-)   "400x80"       ;# geometry and position of no match  window
set myX(geoS)   "700x720"      ;# geometry and position of O-Saft    window
set myX(geoA)   "660x610"      ;# geometry and position of About     window
set myX(geoF)   ""             ;# geometry and position of Filter    window (computed dynamically)
set myX(geoT)   ""             ;#
set myX(minx)   700            ;# O-Saft  window min. width
set myX(miny)   780            ;# O-Saft  window min. height
set myX(lenl)   15             ;# fixed width of labels in Options window
set myX(rpad)   15             ;# right padding in the lower right corner
set myX(padx)   5              ;# padding to right border

set cfg(DESC)   {-- CONFIGURATION GUI style and layout -----------------------}
set cfg(bstyle) {image}        ;# button style:  image  or  text
set cfg(layout) {table}        ;# layout o-saft.pl's results:  text  or  table
                                # see also comment in gui_init()
set cfg(tfont)  {flat9x6}      ;# font used in tablelist::tablelist
set cfg(max53)  4090           ;# max. size of text to be stored in table columns
#   Some combinations of Tcl/Tk and X-Servers are limited in the size of text,
#   which can be stored in Tk's table columns. When such a widget is rendered,
#   the script crashes with following error message:
#       X Error of failed request:  BadAlloc (insufficient resources for operation)
#         Major opcode of failed request:  53 (X_CreatePixmap)
#         Serial number of failed request:  2223
#         Current serial number in output stream:  2255
#   To avoid the crash, large texts (greater than this value) can be stripped.
#   The default value of ~4000 is based on experience.

# RC-END }

if {[info exists env(o_saft_docker_tag)] ==1} { set prg(docker-tag) $env(o_saft_docker_tag);  }
if {[info exists env(o_saft_docker_name)]==1} { set prg(docker-id)  $env(o_saft_docker_name); }

catch {
  set fid [open $prg(INIT) r]
  set cfg(.CFG) [read $fid];    close $fid; # read .o-saft.pl
}

#| configure GUI

set cfg(TIP)    [catch { package require tooltip} tip_msg];  # 0 on success, 1 otherwise!

set IMG(!) [image create photo -data {
  R0lGODlhGAAYAOMOAAAAAAARAQASAQASAgATAQATAgBwLgCBNgCBNwCCNQCCNgCCNwCDNiZ/AP//
  /////yH5BAEKAA8ALAAAAAAYABgAAASE8MlJq6o4W3W1fwvHfZ6oLKRmfkKLmcnTDlRrv6IEBC0g
  2YXMStf7CWiPnETUqAl8suNylFROilHkanh9GpEME9cInU3EVvJ3gkB3umXppCHGYM2UeuUuP4/V
  WRUJHAcZfEgpgHh5b3teUYsmTV1YBDYCfhwGTlgTA4iSFANQJAccKB8RADs=
}]; # [!] 24x24

set IMG(help) ::tk::icons::question
if { [regexp {::tk::icons::question} [image names]] == 0} { unset IMG(help); }
    # reset if no icons there, forces text (see cfg_buttons below)

#et IMG(...)                   ;#  other images are defined in cfg(IMG)

#et myX(minx)  myX(miny)  myX(geoS)     # see gui_init() below
#   myX(buffer) ... NOT YET USED
set myX(buffer) PRIMARY        ;# buffer to be used for copy&paste GUI texts
                                # any ICCCM like: PRIMARY, SECONDARY, CLIPBOARD
                                # or: CUT_BUFFER0 .. CUT_BUFFER7
                                # Hint for X, in particular xterm: .Xresources:
                                #     XTerm*VT100.Translations: #override \
                                #         ... \
                                #         <Btn2Up>: insert-selection(PRIMARY,CLIPBOARD) \
                                #         ... \

set my_bg       "[lindex [. config -bg] 4]"    ;# default background color
                                # this colour is used for buttons too

# define all buttons used in GUI
    # Following table defines the  label text, background colour, image and tip
    # text for each button. Each key is an object name and defines one button.
    #
    # This allows to generate the buttons without these attributes (-text, -bg,
    # -image, etc.), which simplifies the code.  These attributes are set later
    # using  guitheme_set(),  which then also takes care  if there  should be a
    # simple theme (just text and background) or a more sexy one using images.
    # Note:   the key (object name) in following table must be the last part of
    #         the object (widget) name of the button, example: .f.about  .

    #----------+---------------+-------+-------+-------------------------------
    # object    button text colour   image      help text (aka tooltip)
    # name      -text       -bg     -image      guitip_set()
    #----------+-----------+-------+-----------+-------------------------------
array set cfg_buttons "
    {about}     {{!}        $my_bg  {!}         {About $cfg(ICH) $cfg(VERSION)}}
    {help}      {{?}        $my_bg  help        {Open window with complete help}}
    {help_me}   {{?}        $my_bg  {?}         {Open window with help for these settings}}
    {closeme}   {{Quit}     orange  quit        {Close program}}
    {closewin}  {{Close}    orange  close       {Close window}}
    {closetab} {{Close Tab} orange  closetab    {Close this TAB}}
    {loadresult}  {{Load}   lightgreen load     {Load results from file}}
    {saveresult}  {{Save}   lightgreen save     {Save results to file}}
    {saveconfig}  {{Save}   lightgreen save     {Save configuration to file  }}
    {ttyresult}   {{STDOUT} lightgreen stdout   {Print results on systems STDOUT}}
    {reset}     {{Reset}    $my_bg  reset       {Reset configuration to defaults}}
    {filter}    {{Filter}   $my_bg  filter      {Show configuration for filtering results}}
    {tkcolor} {{Color Chooser}  $my_bg tkcolor  {Open window to choose a color}}
    {tkfont}  {{Font Chooser}   $my_bg tkfont   {Open window to choose a font}}
    {host_add}  {{+}        $my_bg  {+}         {Add new line for a host}}
    {host_del}  {{-}        $my_bg  {-}         {Remove this line for a host }}
    {help_home} {{^}        $my_bg  help_home   {Go to top of page (start next search from there)}}
    {help_prev} {{<}        $my_bg  help_prev   {Search baskward for text}}
    {help_next} {{>}        $my_bg  help_next   {Search forward for text}}
    {help_help} {{?}        $my_bg  {?}         {Show help about search functionality}}
    {helpreset} {{Reset}    $my_bg  reset       {Reset/clear list of search texts}}
    {helpsearch}  {{??}     $my_bg  helpsearch  {Text to be searched}}
    {cmdstart}  {{Start}    yellow  cmdstart    {Execute $prg(SAFT) with commands selected in 'Commands' tab}}
    {cmdcheck}  {{+check}   #ffd800 +check    {Execute $prg(SAFT) +check   }}
    {cmdcipher} {{+cipher}  #ffd000 +cipher   {Execute $prg(SAFT) +cipher  }}
    {cmdinfo}   {{+info}    #ffc800 +info     {Execute $prg(SAFT) +info    }}
    {cmdquit}   {{+quit}    #ffc800 +quit     {Execute $prg(SAFT) +quit (debugging only)}}
    {cmdquick}  {{+quick}   #ffc000 +quick    {Execute $prg(SAFT) +quick   }}
    {cmdprotocols} {{+protocols} #ffb800 +protocols {Execute $prg(SAFT) +protocols }}
    {cmdvulns}  {{+vulns}   #ffb000 +vulns    {Execute $prg(SAFT) +vulns   }}
    {cmdversion} {{+version} #fffa00 +version {Execute $prg(SAFT) +version }}
    {docker_status} {{docker status} #00faff status  {Execute $prg(SAFT) status   }}
    {img_txt}   {{image/text} $my_bg {img_txt}  {toggle buttons: text or image}}
";  #----------+-----------+-------+-----------+-------------------------------

    # Note: all buttons as described above,  can be configured also by the user
    # using  cfg(RC).  Configurable are:  text (-text), background colour (-bg)
    # and the tooltip. Because configuering the above table is a bit cumbersome
    # for most users, we provide simple lists with key=value pairs. These lists
    # are: cfg_colors, cfg_texts and cfg_tipps. The settings here are defaults,
    # and may be redefined in cfg(RC) using  cfg_color, cfg_label and cfg_tipp.
    # These lists (arrays in Tcl terms) contain not just the button values, but
    # also values for other objects.  So the lists are initialized here for all
    # other values, and then the values from cfg_buttons are added.
    #
    # array in cfg(RC)  array herein   (see also update_cfg() )
    #     cfg_color     cfg_colors
    #     cfg_label     cfg_texts
    #     cfg_tipp      cfg_tipps

proc _get_btn_txt {key} { global cfg_buttons; return [lindex $cfg_buttons($key) 0]; }
proc _get_btn_bg  {key} { global cfg_buttons; return [lindex $cfg_buttons($key) 1]; }
proc _get_btn_img {key} { global cfg_buttons; return [lindex $cfg_buttons($key) 2]; }
proc _get_btn_tip {key} { global cfg_buttons; return [lindex $cfg_buttons($key) 3]; }

array set cfg_colors "
    DESC        {-- CONFIGURATION colours used in GUI ------------------------}
    osaft       gold
    button      lightyellow
    code        lightgray
    link        blue
    status      wheat
"

array set cfg_texts "
    DESC_search {-- CONFIGURATION texts used in GUI's Help window ------------}
    h_min4chars {Pattern should have more than 3 characters.}
    h_nomatch   {No matches found for}
    h_badregex  {Invalid RegEx pattern}
    DESC        {-- CONFIGURATION texts used in GUI for buttons or labels ----}
    host        {Host\[:Port\]}
    hideline    {Hide complete line}
    c_toggle    {toggle visibility\nof various texts}
"

array set cfg_tipps "
    DESC        {-- CONFIGURATION texts used for tool tips on buttons --------}
    settings    {Open window with more settings}
    layout      {Format used in result TAB}
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
    helpclick   {Click to show in Help window}
    help_mode   {Mode how pattern is used for searching}
    tabFILTER   {
Configure filter for text markup: r, e and # specify how the RegEx should work;
Forground, Background, Font and u  specify the markup to apply to matched text.
Changes apply to next +command.
}
    DESC_misc   {-- CONFIGURATION texts used in GUI for various other texts --}
    f_key       Key
    f_moder     r
    f_modee     e
    f_chars     {#}
    f_regex     RegEx
    f_fg        Foreground
    f_bg        Background
    f_font      Font
    f_u         u
    DESC_opts   {-- CONFIGURATION texts used in GUI for option checkbuttons --}
    --header    {print header line}
    --enabled   {print only enabled ciphers}
    --no-dns    {do not make DNS lookups}
    --no-http   {do not make HTTP requests}
    --no-sni    {do not make connections in SNI mode}
    --no-sslv2  {do not check for SSLv2 ciphers}
    --no-tlsv13 {do not check for TLSv13 ciphers}
    docker-id   {Docker image ID (registry:tag) to be connected}
"; # cfg_tipps; # Note: text for tab* contain new lines.

# now add default to cfg_* as described before
foreach key [array names cfg_buttons] {
    set cfg_colors($key) [_get_btn_bg  $key]
    set cfg_texts($key)  [_get_btn_txt $key]
    set cfg_tipps($key)  [_get_btn_tip $key]
    set cfg_images($key) [_get_btn_img $key]
}

proc _get_color   {key} { global cfg_colors;  return $cfg_colors($key) };
    #? return color name for key from global cfg_colors variable
proc _get_text    {key} { global cfg_texts;   return $cfg_texts($key)  };
    #? return text string for key from global cfg_texts variable
proc _get_tipp    {key} { global cfg_tipps;   return $cfg_tipps($key)  };
    #? return text string for key from global cfg_tipps variable
proc _get_image   {key} { global cfg_images;  return $cfg_images($key) };
    #? return image for key from global cfg_images variablle
proc _get_padx    {key} { global myX;         return $myX($key)        };
    #? return padx value for key from global myX variable

if {[regexp {indows} $tcl_platform(os)]} {
    # Some platforms are too stupid to run our executable prg(SAFT) directly,
    # they need a proper  perl executable to do it. Check for perl.exe in all
    # directories of the  PATH environment variable. If no executable will be
    # found, ask the user to choose a proper one.
    # There are  no more checks  for the selected file. If it is # wrong, the
    # script will bail out with an error later.
    foreach p [split $env(PATH) ";"] {
        set p [file join $p "perl.exe"]
        if {[file isdirectory $p]} { continue }
        if {[file executable  $p]} {
            set prg(PERL)     $p
            break
        }
    }
    if {![file executable $prg(PERL)]} {
        set prg(PERL) [tk_getOpenFile -title "Please choose perl.exe" ]
    }
}
# NOTE:  as Tcl is picky about empty variables, we have to ensure later, that
# $prg(PERL) is evaluated propperly,  in particular when it is empty.  We use
# Tcl's  {*}  evaluation for that.

#| check if prg(SAFT) exists in PATH, +VERSION just prints the version number
#_dbx 3        " $prg(PERL) $prg(SAFT) +VERSION"; # _dbx() not yet defined
catch { exec {*}$prg(PERL) $prg(SAFT) +VERSION } usage;
if {![regexp {^\d\d\.\d\d\.\d\d} $usage]} { # check other PATH
    set osaft "$cfg(DIR)/$prg(SAFT)";       # check in PATH of $argv0
    catch { exec {*}$prg(PERL) $osaft +VERSION }  usage;
    if {![regexp {^\d\d\.\d\d\.\d\d} $usage]} {
        tk_messageBox -icon warning -title "$prg(SAFT) not found" -message "
most parts of the GUI are missing!

!!Hint:
check PATH environment variable."

    } else {
        set prg(SAFT) $osaft;               # found
    }
}

set cfg(DESC)   {-- CONFIGURATION internal data storage ----------------------}
set cfg(CDIR)   [file join [pwd] [file dirname [info script]]]
set cfg(EXEC)   0  ;# count executions, used for object names
    #               # counter also used for number of TABs in $cfg(objT), hence
    #               # TABs with executions start at 3, see create_main()
set cfg(x--x)   0  ;# each option  will have its own entry (this is a dummy)
set cfg(x++x)   0  ;# each command will have its own entry (this is a dummy)
set cfg(winO)   "" ;# object name of Help   window
set cfg(win-)   "" ;# (reserved for future use)
set cfg(winS)   ".";# object name of main   window (usually not used as just .)
set cfg(winA)   "" ;# object name of About  window
set cfg(winF)   "" ;# object name of Filter window
set cfg(winT)   "" ;# (reserved for future use)
set cfg(objS)   "" ;# object name of status line
set cfg(objT)   "" ;# object name of notebook; needed to add more note TABS
set cfg(VERB)   0  ;# set to 1 to print more informational messages from Tcl/Tk
set cfg(DEBUG)  0  ;# set to 1 to print debugging messages
set cfg(TRACE)  0  ;# set to 1 to print program tracing

set cfg(AQUA)   {-- CONFIGURATION Aqua (Mac OS X) ----------------------------}
#   Tcl/Tk on Aqua has some limitations and quirky behaviours
set cfg(confirm) {-confirmoverwrite true};  # must be reset on Aqua
#      myX(rpad)    # used as right padding for widgets in the lower right
                    # corner where there is Aqua's resize icon

set search(DESC)    {-- CONFIGURATION seaching text in O-Saft's help ---------}
set search(text)    "";     # current search text
set search(list)    "";     # list of search texts (managed by spinbox)
set search(curr)     0;     # current index in search(list)
set search(last)    "";     # last search text (used to avoid duplicates)
set search(see)     "";     # current position to see, tuple like: 23.32 23.37
set search(more)     5;     # show addition overview window when more than this search results
set search(mode)    "regex";# search pattern is exact text, or regex, or fuzzy
#   variable names and function names used/capable for searching text in HELP
#   can be found with following patterns:  search.text  search.list  etc.
# tags used in help text cfg(HELP) aka (window) cfg(winO)
    # HELP-search-pos   tag contaning matching text positions (tuple: start end)
    # HELP-search-mark  tag assigned to currently marked search text
    # HELP-search-box   tag assigned to currently paragraph with search text
    # HELP-LNK      tag assigned to all link texts in text
    # HELP-TOC-*    individual tag for a linked line
    # HELP-LNK-T    tag assigned to top of text
    # HELP-HEAD     tag assigned to all header texts (lines)
    # HELP-HEAD-*   individual tag for a header text
    # HELP-TOC      tag assigned to all lines in table of content
    # HELP-TOC-*    individual tag for a TOC line
    # HELP-REF      tag assigned to all TOC reference
    # HELP-XXX-*
    # HELP-CODE     tag assigned to all code texts

set hosts(0)     0; # array containing host:port; index 0 contains counter
set results(0)  ""; # contains raw results of prg(SAFT); results(0) is empty

#_____________________________________________________________________________
#_______________________________________________________ filter definitions __|

#   array name  {description of element used in header line in Filter tab}
set f_key(0)    {Unique key for regex}
set f_mod(0)    {Modifier how to use regex}
set f_len(0)    {Length to be matched (0: all text; -1: complete line to right end)}
set f_bg(0)     {Background color used for matching text (empty: don't change)}
set f_fg(0)     {Foreground color used for matching text (empty: don't change)}
set f_fn(0)     {Font used for matching text (empty: don't change)}
set f_un(0)     {Underline matching text (0 or 1)}
set f_rex(0)    {RegEx to match text}
set f_cmt(0)    {Description of regex}

proc _txt2arr     {str} {
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
}; # _txt2arr

#   Filters to match results are defined as tabular text.
#   For better readability we do not use output of  "o-saft.pl +help=ourstr".
#   A tabular string is used, which is better to maintain than  Tcl arrays.
#   This string is converted to multiple arrays (one array for each line in
#   the string), these array can be simple accessed in Tcl.
#   A filter consist of all elements with same index in each array.
#   This also allows to extend the arrays dynamically.
#   First (0) index in each array is description.

#   use map to replace variables (and short names to fit in 8 characters)

_txt2arr [string map "
    _lGreen lightgreen
    _yellow yellow
    _orange orange
    _sBlue  SteelBlue
    _lBlue  LightBlue
    _lGray  LightGray
    __bold  osaftHead
    _ME_    $prg(SAFT)
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
# FIXME  no  must be first regex in liste here, but still causes problems in toggle_filter
  LOW	-regexp	3	red	{}	{}	0	(LOW|low)	word  LOW   anywhere
  WEAK	-exact	4	red	{}	{}	0	WEAK	word  WEAK  anywhere
  weak	-exact	4	red	{}	{}	0	weak	word  weak  anywhere
 MEDIUM	-regexp	6	yellow	{}	{}	0	(MEDIUM|medium)	word MEDIUM anywhere
  HIGH	-regexp	4	_lGreen	{}	{}	0	(HIGH|high)	word  HIGH  anywhere
 **WARN	-exact	0	_lBlue	{}	{}	0	**WARN	line  **WARN (warning from _ME_)
 !!HINT	-exact	0	_lBlue	{}	{}	0	!!Hint	line  !!Hint (hint from _ME_)
  A	-regexp	1	_lGreen	{}	{}	0	(^A$)	word  A  at end of line
  B	-regexp	1	yellow	{}	{}	0	(^B$)	word  B  at end of line
  C	-regexp	1	_orange	{}	{}	0	(^C$)	word  C  at end of line
  D	-regexp	1	red	{}	{}	0	(^D$)	word  D  at end of line
  ?	-regexp	3	_lGray	{}	{}	0	(^-\?-$)	word -?- at end of line
  NO	-regexp	1	_orange	{}	{}	0	no \([^)]*\)	word  no ( anywhere
  YES	-regexp	3	_lGreen	{}	{}	0	yes	word  yes  at end of line
 == CMT	-regexp	-1	_lGray	{}	__bold	1	^==*	line starting with  == (formatting lines)
  # DBX	-regexp	0	{}	blue	{}	0	^#[^[]	line starting with  #  (verbose or debug lines)
 #[KEY]	-regexp	2	_lGray	gray	{}	0	^#\[[^:]+:\s*	line starting with  #[keyword:]
# ___                                                                   but not:  # [keyword:
  _ME_	-regexp	-1	black	white	{}	0	.*?_ME_.*\n\n	lines contaning program name
 Label:	-regexp	1	{}	{}	__bold	0	^(#\[[^:]+:\s*)?[A-Za-z][^:]*:\s*	label of result string from start of line until :
  perl	-regexp	0	purple	{}	{}	0	^Use of .*perl	lines with perl warnings
  usr1	-regexp	0	{}	{}	{}	0	{}	{}
#------+-------+-------+-------+-------+-------+-------+-------+-------------------------------
#      ** columns must be separated by exactly one TAB **
}]; # filter

#_____________________________________________________________________________
#________________________________________________________________ functions __|

proc _str2obj     {str} {
    #? convert string to valid Tcl object name; returns new string
    set name [regsub -all {[+]} $str  {Y}];     # commands
    set name [regsub -all {[-]} $name {Z}];     # options (mainly)
    set name [regsub -all {[^a-zA-Z0-9_]} $name {X}];
    set name "o$name";  # first character must be lower case letter
    return $name
}; # _str2obj

proc _notTOC      {str} {
    #? return 0 if string should be part of TOC; 1 otherwise
    if {[regexp {^ *(NOT YET|WYSIW)} $str]} { return 1; };  # skip some special strings
    if {[regexp {^ *$} $str]}               { return 1; };  # skip empty
    if {[regexp {^(HIGH|MDIUM|LOW|WEAK|SSL|DHE|OWASP)} [string trim $str]]} { return 1; };
    _dbx 4 " no     = »$str«";
    return 0
}; # _notTOC

proc _count_tuples {str} { return  [expr [expr [llength $str] +1] / 2]  };
    #? return number of touples in given list

proc pwarn        {txt} { puts stderr "**WARNING: $txt"; return }
    #? output WARNING message

proc perr         {txt} { puts stderr "**ERROR: $txt";   return }
    #? output ERROR message

proc putv         {txt} {
    #? verbose output
    global cfg
    if {$cfg(VERB) <= 0} { return; }
    puts stderr "#\[$cfg(ICH)\]:$txt";
    return
}; # putv

proc _ident       {cnt} {
    #? return ident string
    set txt ""
    for {set i 1} {$i <= $cnt} {incr i} {
        set chr " "; # .
        #if {[expr $i % 3] == 0} { set chr "|" }
        append txt $chr
    }
    return $txt
}; # _ident

proc _trace      {args} {
    #? trace output
    global cfg
    if {$cfg(TRACE) <= 0} { return; }
    set cnt  [info level]
    set txt  "$args"
    # convert from: {proc_name arg1 arg2} enter
    #           to: proc_name {arg1 arg2} {                     # dumm } for tcl
    set txt  [regsub {^.([^\s]*)\s*(.*)} $txt "\\1 \{\\2"];
    set txt  [regsub {enter\s*$} $txt "\{"];
    if {[regexp {leave$} $txt]} { set txt  [regsub {^([^\s]*).*} $txt "\\1 \}"]; }
       # just keep function name from noisy leave message:
       #             {proc_name arg1 arg2} 0 noisy text   -->  proc_name
    puts stderr "#\[$cfg(ICH)\][_ident $cnt]$txt";
    return
    # more lazy mode, not implemented ...
    #set func [lindex $args 0]
    #puts stderr "#\[$cfg(ICH)\][_ident $cnt]$func"
    #return
}; # _trace

proc _dbx         {level txt} {
    #? debug output (if $level matches $cfg(DEBUG))
    global cfg
    if {! [expr $cfg(DEBUG) & $level]} { return }
    if {$cfg(DEBUG) < 1} { return }
    # [lindex [info level 1] 0]; # would be simple, but returns wrong
    # name of procedure if it was called within []
    # [info frame -1];           # better
    catch { dict get [info frame -1] proc } me; # name of procedure or error
    if {[regexp {not known in dictionary} $me]} { set me "." }; # is toplevel
    puts stderr "#dbx \[$cfg(ICH)\]$me$txt"
    return
}; # _dbx

proc _trace_add   {cmd} {
    #? initilaize Tcl's tracing for given command or widget
    trace add execution $cmd enter _trace
    trace add execution $cmd leave _trace
    return
}; # _trace_add

proc trace_commands  {} {
    #? initilaize Tcl's tracing for our procs
    append _trace_cmds "[info procs create*] "
    append _trace_cmds "[info procs osaft*] "
    append _trace_cmds "[info procs search*] "
    append _trace_cmds "read_images remove_host www_browser show_window guitheme_init"
    foreach _cmd $_trace_cmds {
        if {[regexp "\(create_\(tip\)\)" $_cmd]} { continue }
        _trace_add $_cmd
    }
    _trace_add read_images
    return
}; # trace_commands

proc trace_buttons   {} {
    #? initilaize Tcl's tracing for all buttons
    foreach obj [info commands] {
        if {![regexp {^\.}  $obj]}  { continue }
        switch [winfo class $obj] {
            {Button}    { _trace_add $obj }
        }
    }
    return
}; # trace_buttons

proc read_images  {theme}   {
    #? read $cfg(IMG) if exists and not already done
    _dbx 2 "{$theme}"
    global cfg IMG
    #  if the file does not exist, the error is silently catched and ignored
    if [info exists cfg(IMGSID)] { puts "IMG da $cfg(IMGSID)" }
    if [info exists cfg(IMGSID)] { return };# already there
    if {$theme eq "image"} {
       set rcfile [regsub "$cfg(ICH)$" $cfg(ME) "$cfg(IMG)"];   # must be same path
       _dbx 4 " IMG $rcfile"
       if {[file isfile $rcfile]} {
           catch { source $rcfile } error_txt
       } else {
           pwarn "$cfg(IMG) not found; using traditional buttons"
       }
    }
    _dbx 4 " IMG    = [array names IMG]"
    return
}; # read_images

proc update_cfg   {}    {
    #? legacy conversion of old (pre 1.86) keys from cfg(RC) aka .o-saft.tcl
    #
    # Until version 1.84, respectively 1.6 of cfg(RC), the variables in cfg(RC)
    # were identical to the ones used herein:
    #   cfg_color,  cfg_label, cfg_tipp
    # As cfg(RC) will only be sourced, it needs to have the complete definition
    # of each of these variables, otherwise we may run into some syntax errors.
    # Starting with version 1.86, the variables herein have been renamed to:
    #   cfg_colors, cfg_texts, cfg_tipps
    # and also some keys have been renamed.
    # This function copies the settings from cfg(RC) to the internal variables.
    # By doing this, the old keys are converted automatically (see switch cases
    # below).
    # Finally we remove the variables set by cfg(RC).
    #
    _dbx 2 "{}"
    global cfg
    if {[info exists cfg(RCSID)]==1} {
        # cfg(RCSID) is defined in .o-saft.tcl, warn if old one
        _dbx 4 " RCmin$cfg(RCmin) > RCSID$cfg(RCSID) ?"
        if {$cfg(RCmin) > $cfg(RCSID)} {
            tk_messageBox -icon warning -title "$cfg(RC) version $cfg(RCSID)" \
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
    global cfg_tipps cfg_tipp
    foreach key [array names cfg_tipp] {
        set value $cfg_tipp($key)
        switch -exact $key {
          {start}       { set cfg_tipps(cmdstart)   $value }
          {closew}      { set cfg_tipps(closewin)   $value }
          {showfilterconfig}  { set cfg_tipps(filter) $value }
          {resetfilterconfig} { set cfg_tipps(reset)  $value }
          {goback}      { set cfg_tipps(help_prev)  $value }
          {goforward}   { set cfg_tipps(help_next)  $value }
          {search}      { set cfg_tipps(helpsearch) $value }
          {choosecolor} { set cfg_tipps(tkcolor)    $value }
          {choosefont}  { set cfg_tipps(tkfont)     $value }
          {plus}        { set cfg_tipps(host_add)   $value }
          {minus}       { set cfg_tipps(host_del)   $value }
          default       { set cfg_tipps($key)       $value }
        }
    }
    array unset cfg_tipp
    global myX cfg_geo
    foreach key [array names cfg_geo] {
        set value $cfg_geo($key)
        switch -exact $key {
          {minus}       { set cfg_texts(host_del)   $value }
          default       { set myX($key)             $value }
        }
    }
    array unset cfg_geo
    global cfg cfg_cmd
    foreach key [array names cfg_cmd] {
        set value $cfg_cmd($key)
        switch -exact $key {
          {minus}       { set cfg_texts(host_del)   $value }
          default       { set cfg($key)             $value }
        }
    }
    array unset cfg_geo
   return
}; # update_cfg

# if {$cfg(TIP)==1} { # use own tooltip from: http://wiki.tcl.tk/3060?redir=1954

proc tooltip      {w help}  {
    bind $w <Any-Enter> "after 1000 [list tooltip:show %W [list $help]]"
    bind $w <Any-Leave> "destroy %W.balloon"
    return
}; # tooltip

proc tooltip:show {w arg}   {
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
    return
}; # tooltip:show
#
# # Example:
# button  .b -text Exit -command exit
# tootip  .b "Push me if you're done with this"
# pack    .b
#
# }

proc gui_set_disabled {w}   {
    #? set widget to disabled state (mode)
    $w config -state disabled
    return
}; # gui_set_disabled

proc gui_set_readonly {w}   {
    #? set widget to readonly state (mode)
    # The definition of "read-only" here is, that any action or event for the
    # widget is allowed, except changing its content anyhow  (delete, insert,
    # etc.). Selecting, highlighting is not considered as a change.
    # This can accomplished simply with:
    #   $w config -state disabled
    # Unfortunately, this does not work as expected on Mac OS X's Aqua. There
    # it also disables highlighting and selecting, for example copying to the
    # clipboard (cutbuffer).
    # Hence following workaround is used, which simply disables all functions
    # for events and sets them to do nothing.
    # This works on all platforms (*IX, Windows, Mac OS X Aqua).
    foreach event {<KeyPress> <<PasteSelection>>} { bind $w $event break }
    return
}; # gui_set_readonly

proc gui_init     {}    {
    #? initialize GUI
    _dbx 2 "{}"
    global cfg prg myX argv
    if {[catch { package require tablelist } err]} {
        pwarn "'package tablelist' not found, probably 'tklib' missing; using text layout"
        set cfg(layout) {text}
            # cfg(layout) used in create_tab() and create_filtertab()
            # it's hardcoded set to {text} here if package is missing, that's
            # working for create_filtertab() as the widgets there are created
            # only once at startup.
            # Changing cfg(layout) in the GUI later does only affect creating
            # tables in the result tab after  osaft_exec(), and will not harm
            # widgets or functionality created by create_filtertab().
    }
    font create osaftHead   {*}[font config TkFixedFont;]  -weight bold
    font create osaftBold   {*}[font config TkDefaultFont] -weight bold
    font create osaftSlant  {*}[font config TkFixedFont]   -slant italic
    if {0 == $prg(option)} {    # only if not done in RC-file
        option add *Button.font osaftBold  ;# if we want buttons more exposed
        option add *Label.font  osaftBold  ;# ..
        option add *Text.font   TkFixedFont;
    }

    # configure according real size
    set __x         [lindex [wm maxsize .] 0]
    set __y         [lindex [wm maxsize .] 1]
    if {$__y < $myX(miny)} { set myX(miny) $__y  }
    if {$__x < $myX(minx)} { set myX(minx) $__x  }
    if {$__x > 1000 }      { set myX(minx) "999" }
    set myX(geoS)   "$myX(minx)x$myX(miny)"

    set __native    "";
    # next switch is ugly workaround to detect special start methods ...
    # it also does some special setup for MacOSX
    switch [tk windowingsystem] {
        {win32} { set __native "start" }
        {win64} { set __native "start" }
        {aqua}  -
        {Aqua}  { set __native "open"
                  set cfg(confirm) {};        # Aqua's tk_save* has no  -confirmoverwrite
                  if {[regexp -- {-(img|image)} $argv]} {
                      tk_messageBox -icon warning \
                          -message "using images for buttons is not recomended on Aqua systems"
                  } else {
                      set cfg(bstyle) "text"; # text by default, because Aqua looks nice
                  }
                  set myX(miny)   770;        # because fonts are bigger by default
                }
    }
    set myX(geoS)   "$myX(minx)x$myX(miny)"

    # find proper font for tablelist::tablelist; MacOSX is strange ...
    # usually we should have:  flat6x4, flat7x4, flat7x5, flat7x7, flat8x5,
    #                          flat9x5, flat9x6, flat9x7, flat10x6,
    #                          photo7x7, sunken8x7, sunken10x9, or sunken12x11
    # if no font is found, default will be used, which results in a Tcl error
    foreach f "flat9x5 flat9x6 flat9x7 flat10x6 flat8x5" {
        if {[catch {tablelist::tablelist .ttest -arrowstyle $f} err]} { continue }
        set cfg(tfont) $f
        destroy .ttest
        break
    }
    _dbx 4 " table font = $cfg(tfont)"

    # search browser, first matching will be used
    foreach bin " $__native \
            firefox chrome chromium iceweasel konqueror mozilla \
            netscape opera safari webkit htmlview www-browser w3m" {
        set binary [lindex [auto_execok $bin] 0];   # search in $PATH
        _dbx 4 " browser= $bin $binary"
        if {[string length   $binary]} {
            set prg(BROWSER) $binary
            break
        }
    }

    return
}; # gui_init

proc guitip_set   {w txt}   {
    #? add tooltip message to given widget
    global cfg
    if {$cfg(TIP)==1} {     # package tooltip not available, use own one
        tooltip $w "$txt"
    } else {
        set txt [regsub {^-} $txt " -"];# texts starting with - cause problems in tooltip::tooltip
        tooltip::tooltip $w "$txt"
    }
    return
}; # guitip_set

proc guitheme_set {w theme} {
    #? set attributes for specified object
    # last part of the Tcl-widgets is key for array cfg_buttons
    _dbx 2 "{$w, $theme}"
    global cfg cfg_buttons IMG
    # text and tip are always configured
    set key [regsub {.*\.([^.]*)$} $w {\1}];    # get trailer of widget name
    set val [_get_tipp  $key]; if {$val ne ""} { guitip_set   $w  $val }
    set val [_get_text  $key]; if {$val ne ""} { $w config -text  $val }
    if {[regexp {docker status$} $val]} { $w config -width 10 }; # FIXME: quick&dirty, not really necessary
    set val [_get_image $key]; if {![info exists IMG($val)]} { set theme "text" }
    _dbx 4 " $w\t-> $key\t$theme\t-> $val"
    if {$theme eq "text"} {
        set val [_get_color  $key];
        if {$val ne ""} { $w config -bg    $val }
        $w config -image {} -height 1 -relief raised
    }
    if {$theme eq "image"} {
        if {$val ne ""} {
            set h   30
            if {![regexp {^::tk} $IMG($val)]} { set h 20 }
            $w config -image $IMG($val) -relief flat
            $w config -height $h;       # always set image height
        }
    }
    return
}; # guitheme_set

proc guitheme_init  {theme} {
    #? configure buttons with simple text or graphics
    _dbx 2 "{$theme}"
    global cfg_buttons
    # Search for all Tcl widgets (aka commands), then check if tail of command
    # (part right of right-most .) exists as key in array  cfg_buttons.  If it
    # exits, then use values defined in  cfg_buttons  to set attributes of the
    # widget. First build a regex which matches all widget names of buttons.
    set rex [join [array names cfg_buttons] "|"]
    set rex [join [list {\.(} $rex {)$}] ""]
    _dbx 4 ": regex = $rex"
    foreach obj [info commands] {
        if {![regexp {^\.}  $obj]}  { continue }
        if {![regexp $rex   $obj]}  { continue }
        if { [regexp {^\.$} $obj]}  { continue }
        guitheme_set $obj $theme
    }
    return
}; # guitheme_init

proc guicursor_set {cursor} {
    #? set cursor for toplevel and tab widgets and all other windows
    global cfg
    foreach w [list . objT objS winA winF winO] {
        if {$w ne "."} { set w $cfg($w) }
        if {$w eq ""}  { continue }
        # now get all children too
        foreach c "$w [info commands $w.*]" {
            if {$c eq ""}  { continue }
            if {[regexp -all {\.} $c] > 2} { continue };    # only first level
            #if {[lindex [$c config -cursor] 4] eq ""}
            catch {  $c config -cursor $cursor };   # silently discard errors
        }
    }
    return
}; # guicursor_set

proc guistatus_set {val}    {
    #? add text to status line
    global cfg
    if {$cfg(quit) == 1 } { return }; # no GUI update
    $cfg(objS) config -state normal
    $cfg(objS) insert end "$val\n"
    $cfg(objS) see "end - 2 line"
    gui_set_readonly $cfg(objS)
    update idletasks;       # enforce display update
    return
}; # guistatus_set

proc docker_args  {}        {
    #? if in "docker mode" pass image ID to Docker;
    # note that docker specific options must be before o-saft.pl commands or options
    global prg
    set do  {}
    if {[regexp {\-docker$} $prg(SAFT)]} {
        lappend do "-id=$prg(docker-id)"
        #lappend do "-tag=$prg(docker-tag)"
        # FIXME: need to distinguish if --id= or --tag= was specified
    }
    return $do
}; # docker_args

proc toggle_cfg   {w opt val} {
    #? use widget config command to change options value
    if {$val ne {}} { $w config $opt $val; }
    return 1
}; # toggle_cfg

proc toggle_filter_text {w tag val line} {
    #? toggle visability of text tagged with name $tag in text widget
    # note that complete line is tagged with name $tag.l (see apply_filter)
    _dbx 4 " $w tag config $tag -elide [expr ! $val]"
    global cfg
    #if {$line==0} {
        #$w tag config $tag   -elide [expr ! $val]; # "elide true" hides the text
    #}
    if {[regexp {\-(Label|#.KEY)} $tag]} {
        $w tag config $tag   -elide [expr ! $val];  # hide just this pattern
        # FIXME: still buggy (see below)
        return;
    }
    # FIXME: if there is more than one tag associated with the same range of
    # characters (which is obviously for $tag and $tag.l), then unhiding the
    # tag causes the $tag no longer accessable. Reason yet unknown.
    # Hence we only support hiding the complete line yet.
    $w tag config $tag.l -elide [expr ! $val]
    return
}; # toggle_filter_text

proc toggle_filter_table {w tag val} {
    #? toggle visability of text tagged with name $tag in text widget
    _dbx 4 " $w rowcget  $tag $val"
    global cfg
    # toggling a list of rows could be as simple as
    #   $w togglerowhide $cfg($tag)
    # but some lines are in multiple lists, so each line's toggle state will
    # be checked and changed only if different from given $val,  this avoids
    # unexpected toggles
    # FIXME: checkbutton in Filter window is wrong now (if multiple lists)
    foreach n $cfg($tag) {
        if {[$w rowcget  $n -hide] != $val} { continue }
        $w togglerowhide $n
    }
    return
}; # toggle_filter_table

proc toggle_filter  {w tag val line} {
    #? toggle visability of text tagged with name $tag
    _dbx 2 "{$w $tag $val $line}"
    global cfg
    switch $cfg(layout) {
        text    { toggle_filter_text  $w $tag $val $line }
        table   { toggle_filter_table $w $tag $val }
    }
    return
}; # toggle_filter

proc apply_filter_text  {w} {
    #? apply filters for markup in output, data is in text widget $w
    # set tag for all texts matching pattern from each filter
    # also sets a tag for the complete line named with suffix .l
    _dbx 2 "{$w}"
    global cfg
    global f_key f_mod f_len f_bg f_fg f_rex f_un f_fn f_cmt; # lists containing filters
    foreach {k key} [array get f_key] {
        if {$k eq 0} { continue };
        # extract values from filter table for easy use
        #set key $f_key($k)
        set mod $f_mod($k)
        set len $f_len($k)
        set rex $f_rex($k)
        set fg  $f_fg($k)
        set bg  $f_bg($k)
        set nr  $f_un($k)
        set fn  $f_fn($k)
        if {$key eq ""} { continue };   # invalid or disabled filter rules
        if {$rex eq ""} { continue };   # -"-
        _dbx 4 " $key : /$rex/ $mod: bg=$bg, fg=$fg, fn=$fn"
        # anf contains start, end corresponding end position of match
        set key [_str2obj [string trim $key]]
        set anf [$w search -all $mod -count end "$rex" 1.0]
        set i 0
        foreach a $anf {
            set e [lindex $end $i];
            incr i
            if {$key eq "NO" || $key eq "YES"} {incr e -1 }; # FIXME very dirty hack to beautify print
            $w tag add    HELP-$key.l "$a linestart" "$a lineend"
            if {$len<=0} {
                if {$len<0} {
                   $w tag add HELP-$key $a  "$a + 1 line"; # complete line to right end
                } else {
                   $w tag add HELP-$key $a  "$a + 1 line - 1 char"; # all text in the line
                  #$w tag add HELP-$key $a  "$a lineend"; # does not work
                }
            } else {
               $w tag add HELP-$key     $a  "$a + $e c"
            }
            $w tag  raise HELP-$key.l HELP-$key
        }
        _dbx 4 " $key: $rex F=$fg B=$bg U=$nr fn=$fn"
        if {$fg ne ""}  { $w tag config HELP-$key -foreground $fg }
        if {$bg ne ""}  { $w tag config HELP-$key -background $bg }
        if {$nr ne "0"} { $w tag config HELP-$key -underline  $nr }
        if {$fn ne ""}  { $w tag config HELP-$key -font       $fn }
    }
    return
}; # apply_filter_text

proc apply_filter_table {w} {
    #? apply filters for markup in output, data is in table widget $w
    # FIXME: this is ugly code because the regex in f_rex are optimized for
    # use in Tcls's text widget, the regex must be changed to match the values
    # in Tcl's tablelist columns
    _dbx 2 "{$w}"
    global cfg
    global f_key f_mod f_len f_bg f_fg f_rex f_un f_fn f_cmt; # lists containing filters
    foreach {k key} [array get f_key] {
        set key [_str2obj [string trim $key]]
        set cfg(HELP-$key) ""
    }
    set nr  -1
    # lines look like: 009 {Certificate Common Name} mail.google.com {}
    foreach l [$w get 0 end] {
        #set nr    [lindex $l 0];# cannot use stored number, because of leading 0
        incr nr
        set __nr  [lindex $l 0];# number given by get
        set label [lindex $l 1]
        set value [lindex $l 2]
        set cmt   [lindex $l 3]
        if {[regexp -nocase ^no $value] && [regexp -nocase ^(LOW|WEAK|MEDIUM|HIGH) $cmt]} { continue }
            # no colour for lines with ciphers (from +cipher) which are not supported
        if {[regexp -nocase ^none $value]} { continue };# NONE, None are valid values
        set col      1
        set matchtxt $label
        foreach {k key} [array get f_key] {
            if {$k eq 0} { continue };
            # extract values from filter table for easy use
            #set key $f_key($k)
            set mod $f_mod($k) ;# not used here
            set len $f_len($k) ;# not used here
            set rex $f_rex($k)
            set fg  $f_fg($k)
            set bg  $f_bg($k)
            set un  $f_un($k)
            set fn  $f_fn($k)  ;# does not work in tablelist
            if {$key eq ""} { continue };   # invalid or disabled filter rules
            if {$rex eq ""} { continue };   # -"-
            _dbx 4 " $key : /$rex/ bg=$bg, fg=$fg, fn=$fn"
            # finding the pattern in the  table's cells is not as simple as in
            # texts (see apply_filter_text() above), that's why the regex must
            # be applied to the proper column: $col and $matchtxt is needed
            switch -exact $key {
                "no"        { continue }
                "_ME_"      -
                "Label:"    -
                "**WARN"    -
                "!!Hint"    -
                "== CMT"    -
                "# DBX"     { set col 1; set matchtxt $label }
                "NO"        { set col 2; set matchtxt $value; set rex ^no }
                "YES"       { set col 2; set matchtxt $value }
            }
            set rex [regsub {^(\*\*|\!\!)} $rex {\\\1}];
                # regex are designed for Tcl's text search where we have the
                # -exact or -regex option; this regex must be converted for
                # use in Tcl's regexp: need to escape special characters
            if {[regexp         ^(A|B|C|D|-?-)$         $key]} { set col 2; set matchtxt $value }
            if {[regexp -nocase ^(LOW|WEAK|MEDIUM|HIGH) $key]} { set col 3; set matchtxt $cmt }
            if {[regexp -nocase -- $rex "$matchtxt"]} {
                if {$col == 1} {
                    # if the match is against the first column, colourize the whole line
                    if {$fg ne ""}  { $w rowconfig  $nr -foreground $fg }
                    if {$bg ne ""}  { $w rowconfig  $nr -background $bg }
                    if {$fn ne ""}  { $w rowconfig  $nr -font       $fn }
                   #if {$un ne "0"} { $w cellconfig $nr,$col -underline  $un }
                } else {
                    if {$fg ne ""}  { $w cellconfig $nr,$col -foreground $fg }
                    if {$bg ne ""}  { $w cellconfig $nr,$col -background $bg }
                    if {$fn ne ""}  { $w cellconfig $nr,$col -font       $fn }
                   #if {$un ne "0"} { $w cellconfig $nr,$col -underline  1   }
                }
                set key [_str2obj [string trim $key]]
                lappend cfg(HELP-$key) $nr
            }
        }
    }
    return
}; # apply_filter_table

proc apply_filter    {w layout cmd} {
    #? apply filters for markup in output tab, data is in text or table widget $w
    _dbx 2 "{$w, $layout, $cmd}"
    global cfg
    switch $layout {
        text    { apply_filter_text  $w }
        table   { apply_filter_table $w }
    }
    return
}; # apply_filter

proc show_window       {w}          {
    #? show window near current cursor position
    set y   [winfo pointery $w]; incr y 23
    set x   [winfo pointerx $w]; incr x 23
    wm geometry  $w "+$x+$y"
    wm deiconify $w
    return
}; # show_window

proc www_browser       {url}        {
    #? open URL in browser, uses system's native browser
    global cfg prg
    if {[string length $prg(BROWSER)] < 1} { pwarn "no browser found"; return; }
    #win32# [tk windowingsystem]  eq "win32"
    #win32# { does not work with ActiveTcl
    #win32# package require twapi_com
    #win32# set ie [twapi::comobj InternetExplorer.Application]
    #win32# puts "IE $ie"
    #win32# $ie Visible true
    #win32# set ie [twapi::comobj Firefox.Application]
    #win32# puts "IE $ie"
    #win32# $ie Visible true
    #win32# }
    #win32# { works with ActiveTcl
    #win32# folgendes funktioniert, aber IE läuft im Vordergrund, d.h. Rest fehlt
    #win32# package require dde
    #win32# dde execute iexplore WWW_OpenURL http://www.tcl.tk/
    #win32# }
    putv  " exec {*}$prg(BROWSER) $url & "
    catch { exec {*}$prg(BROWSER) $url & }
    return
}; # www_browser

proc bind_browser      {w tagname}  {
    #? search for URLs in $w, mark them and bind key to open browser
    global cfg
    set anf [$w search -regexp -all -count end {\shttps?://[^\s]*} 1.0]
    set i 0
    foreach a $anf {
        set e [lindex $end $i];
        set t [string trim [$w get $a "$a + $e c"]];
        set l [string length $t]
        incr i
        $w tag add    $tagname     $a "$a + $e c"
        $w tag add    $tagname-$i  $a "$a + $e c"
        $w tag config $tagname-$i -foreground [_get_color link]
        $w tag bind   $tagname-$i <ButtonPress> "www_browser $t"
        if {$cfg(TIP)==0} { tooltip::tooltip $w -tag $tagname-$i "Open in browser: $t" }
            # cannot use guitip_set as we want to bind to $tagnmae and not $w
    }
    return
}; # bind_browser

proc create_selected   {title val}  {
    #? opens toplevel window with selectable text
    global cfg myX
    global __var;   # must be global
    set w    .selected
    toplevel $w
    wm title $w "$cfg(TITLE): $title"
    wm geometry  $w 200x50
    pack [entry  $w.choosen  -textvariable __var -relief flat]
    pack [button $w.closewin -command "destroy $w"] -side right -padx $myX(rpad)
    guitheme_set $w.closewin $cfg(bstyle)
    guitip_set   $w.choosen "[_get_tipp choosen] $title"
    set __var "$val"
    return 1
}; # create_selected

proc create_window     {title size} {
    #? create new toplevel window with given title and size; returns widget
    # special handling for windows with title "Help" or "About"
    global cfg myX
    set this    .[_str2obj $title]
    if {[winfo exists $this]}  { return ""; }; # do nothing
    toplevel     $this
    wm title     $this "$cfg(TITLE): $title"
    wm iconname  $this "o-saft: $title"
    wm geometry  $this $size
    pack [frame  $this.f1] -fill x -side bottom
    pack [button $this.f1.closewin -command "destroy $this"] -padx $myX(rpad) -side right
    guitheme_set $this.f1.closewin $cfg(bstyle)
    if {$title eq "Help" || $title eq "About"} { return $this }
    if {[regexp {^Filter} $title]}             { return $this }

    # all other windows have a header line and a Save button
    pack [frame  $this.f0    -borderwidth 1 -relief sunken]    -fill x -side top
    pack [label  $this.f0.t  -text $title   -relief flat  ]    -fill x -side left
    pack [button $this.f0.help_me     -command "create_help {$title}"] -side right
    pack [button $this.f1.saveconfig  -command {osaft_save "CFG" 0}]   -side left
    # FIXME: wiget paremeter $tbl missing for osaft_save
    guitheme_set $this.f1.saveconfig $cfg(bstyle)
    guitheme_set $this.f0.help_me    $cfg(bstyle)
    return $this
}; # create_window

# poor man's OO for created windows
proc create_window:title    {w txt} {
    #? destroy "Save" button in created window
    global cfg
    wm title     $w "$cfg(TITLE): $txt"
    wm iconname  $w "o-saft: $txt"
    return
}
proc create_window:helpcmd  {w cmd} { $w.f0.help_me    config -command $cmd; return; }
    #? configure new command for "?" button in created window
proc create_window:savecmd  {w cmd} { $w.f1.saveconfig config -command $cmd; return; }
    #? configure new command for "Save" button in created window
proc create_window:noclose  {w}     { destroy $w.f1.closewin;   return; }
    #? destroy "Close" button in created window
proc create_window:nohelp   {w}     { destroy $w.f0.help_me;    return; }
    #? destroy "?" button in created window
proc create_window:nosave   {w}     { destroy $w.f1.saveconfig; return; }
    #? destroy "Save" button in created window

proc create_host  {parent}          {
    #? frame with label and entry for host:port; $nr is index to hosts()
    global cfg hosts myX
    set host  $hosts($hosts(0))
    incr hosts(0)
    _dbx 4 " host($hosts(0))= $host"
    set this $parent.ft$hosts(0)
          frame  $this
    grid [label  $this.lh -text [_get_text host]] \
         [entry  $this.eh -textvariable hosts($hosts(0))] \
         [button $this.host_add -command "create_host {$parent};"] \
         [button $this.host_del -command "remove_host $this; set hosts($hosts(0)) {}"] \

    guitheme_set $this.host_add $cfg(bstyle)
    if {$hosts(0)==1} {
        # first line has no {-} but {about}
        grid forget  $this.host_del
        grid [button $this.about -command "create_about"] -row 0
        grid config  $this.about -column 4 -sticky e  -padx "1 $myX(padx)"
        guitheme_set $this.about $cfg(bstyle)
    } else {
        guitheme_set $this.host_del $cfg(bstyle)
    }
    grid config  $this.eh -column 1 -sticky ew
    grid columnconfigure    $this 1 -weight 1
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
    return
}; # create_host

proc remove_host  {parent}          {
    #? destroy frame with label and entry for host:port
    catch {destroy $parent.eh $parent.bp $parent.bm $parent.lh $parent}
    return
}; # remove_host

proc create_text  {parent content}  {
    #? create scrollable text widget and insert given text; returns widget
    _dbx 2 "{$parent, ...}"
    set this    $parent
    text        $this.t -wrap char -yscroll "$this.s set";  # -width 40 -height 10
    scrollbar   $this.s -orient vertical -command "$this.t yview"
    #set txt     [regsub -all {\t} $content "\t"];   # tabs are a pain in Tcl :-(
    # insert content
    $this.t insert end $content
    $this.t config -font TkFixedFont
    gui_set_readonly $this.t
    pack $this.s -side right -fill y  -pady 2 -padx {0 2} -in $this
    pack $this.t -fill both -expand 1 -pady 2 -padx {2 0} -in $this
    return $this
}; # create_text

proc create_table {parent content}  {
    #? create scrollable table widget and insert given text; returns widget
    #
    # create a table with 4 columns: Nr Label Value Comment
    # the Nr column is used to revert any sorting
    # the text for Label column is extracted from the line, anything left of :
    # the text for Value column is extracted from the line, anything right of :
    #   the value is then further separated in a Value and a Comment (if any)
    # lines from +cipher command consist of a cipher, a value and a severity
    #   the cipher becomes the Label column
    # lines starting with = or # are currently ignored, because Tcl's tablelist
    # has no "colspan" functionality and therfore do not fit into the 4 colums
    _dbx 2 "{$parent, ...}"
    _dbx 16 " content=»$content«"
    global  cfg prg
    set this    $parent.ft
    frame $this
    pack [scrollbar $this.x -orient horizontal -command [list $this.t xview]] -side bottom -fill x
    pack [scrollbar $this.y -orient vertical   -command [list $this.t yview]] -side right  -fill y
    pack [tablelist::tablelist $this.t   \
             -exportselection true \
             -selectmode extended  \
             -selecttype row    \
             -arrowcolor black  \
             -background white  \
             -borderwidth 1     \
             -stripebackground lightgray \
             -arrowstyle $cfg(tfont) \
             -labelrelief solid   \
             -labelfont osaftBold \
             -labelpady   3     \
             -labelcommand tablelist::sortByColumn -showarrow true \
             -movablecolumns true \
             -movablerows    true \
             -xscrollcommand [list $this.x set] \
             -yscrollcommand [list $this.y set] \
             -font  TkFixedFont \
             -spacing 1 \
             -height 25 \
             -width 150 \
             -stretch 2 \
         ] -side left -fill both -expand yes
    # insert header line
    set head [list Nr Label Value Comment]
    foreach f $head { lappend titles 0 $f }
    $this.t config -columns $titles
    $this.t columnconfigure 0 -width  3 ;# -hide true ;# line nr
    $this.t columnconfigure 1 -width 50            ;# label
    $this.t columnconfigure 2 -width 25            ;# value
    # insert content
    set n 1;   # add uniwue number to each line, for initial sorting
    set ssl "";# TODO: ungly hack: need to detect header line with protocol
    foreach line [split $content "\n"] {
        # content consist of lines separated by \n , where each line is a label
        # and a value separated by a tab (and additional spaces for formatting)
        # in tabular context, only label and value is required; no tabs, spaces
        if {[regexp {^\s*$} $line]} { continue };# skip empty lines
        #_dbx 16 " line   = $line"
        set nr [format %03d [incr n]]
            # integer must have leading 0, otherwise sorting of tablelist fails
            # no more than 999 lines are expected, may be more with --v --trace
        set stretch 0
        set line [regsub {^(=+)} $line {\1:}];  # simulate label: value
        if {[regexp {^[=#]+} $line]} {
            $this.t insert end [list $nr $line]
            $this.t togglerowhide end
            $this.t cellconfigure end,0 -stretch 1 ;# FIXME: does not work
            if {[regexp {Ciphers:\s*Checking} $line]} {
                # +cipher header line containing protocol, like:
                # === Ciphers: Checking TLSv12 ===
                # TODO: matches content, only default settings detected
                set ssl [lindex [split $line " "] 3];# remember current protocol
                #dbx puts "C $ssl"
            }
            # tablelist does not support "colspan", hence lines are ignored
            continue
            set col2 $col1
            set col1 ""
            # ?# set col0 "$col0 $col1"
            # ?# set stretch 1
            # ?# tablelist kann kein "colspan"
        }
        if {[regexp $prg(SAFT).* $line]} {
            $this.t insert end [list $nr $line]
            $this.t togglerowhide end
            $this.t cellconfigure end,0 -stretch 1 ;# FIXME: does not work
            # tablelist does not support "colspan", hence lines are ignored
            continue
            set col2 $col0
            set col1 ""
            set col0 ""
        }
        if {[regexp {:}  $line]} {  # line not from +cipher
            set col2 ""
            set col0 [regsub {^([^:]+):.*}  $line {\1}] ; # get label
            set col1 [regsub {^[^:]+:\s*} $line {}] ;   # get label
            #if {[regexp -nocase {^(yes|no\s+\()} $col1]}
                # NOTE: there my be values like "No other text ..."
            if {[regexp -nocase {^(yes|no)} $col1]} {
                # lines from +check
                # split yes|no from rest of text
                set col2 [regsub {^[^\s]+\s+} $col1 {}]
                set col1 [regsub -nocase {^(yes|no)\s.*} $col1 {\1}]
                if {$col1 eq $col2} { set col2 "" };# if there is no col2
            }
            if {[regexp {^[!\*]+} $line]} {
                # warning and hint lines
                set col2 $col1
                set col1 ""
            }
            if {[regexp {^(SSL|TLS)v} $col0]} {
                # summary lines of cipher checks
                set col2 $col1
                set col1 ""
            }
            if {$cfg(max53) < [string length $col2]} {
                pwarn "comment for '$col0' to large (> $cfg(max53)); stripped"
                set col2 "[string range $col2 1 $cfg(max53)] ..\[stripped\].." ;# see cfg(max53)
                # FIXME: need to store orignal text somewhere (notin table)
            }
            set line [list $nr $col0 $col1 $col2]
        } else {
            # lines containing cipher, like:
            #   AES128-SHA256 yes HIGH
            append line " $ssl"                    ;# add protocol
            set line [regsub {^[ \t]+} $line {}]   ;# remove trailing spaces
            set line [regsub -all {([ \t])+} $line { }]
            set cols [split $line " "]
            set line "$nr $cols"
        }
        set line [regsub -all \t $line {}] ;# remove tabs
        $this.t insert end $line
    }
    pack $this -side top
    return $this
}; # create_table

proc create_filterhead  {parent txt tip col} {
    #? create a cell for header line in the filter grid
    # note: txt must be the index to cfg_texts array, we cannot pass the value
    #       directly because it then must be converted to an object name also,
    #       see next setting of $this
    set this $parent.$txt
    grid [label $this -text [_get_tipp $txt] -relief raised -borderwidth 1 ] -sticky ew -row 0 -column $col
    guitip_set  $this $tip
    return
}; # create_filterhead

proc create_filtertext  {parent cmd}    {
    #? create table with filter data
    global cfg
    global f_key f_mod f_len f_bg f_fg f_rex f_un f_fn f_cmt; # filters
    set this $parent
    # { set header line with descriptions
        create_filterhead $this f_key    $f_key(0) 0
        create_filterhead $this f_moder "$f_mod(0) (-regexp)" 1
        create_filterhead $this f_modee "$f_mod(0) (-exact)"  2
        create_filterhead $this f_chars  $f_len(0) 3
        create_filterhead $this f_regex  $f_rex(0) 4
        create_filterhead $this f_fg     $f_fg(0)  5
        create_filterhead $this f_bg     $f_bg(0)  6
        create_filterhead $this f_font   $f_fn(0)  7
        create_filterhead $this f_u      $f_un(0)  8
    # }
    foreach {k key} [array get f_key] { # set all filter lines
        if {$k eq 0} { continue };
        #set key $f_key($k)
        set key [_str2obj [string trim $key]]
        set mod $f_mod($k)
        set len $f_len($k)
        set rex $f_rex($k)
        set fg  $f_fg($k)
        set bg  $f_bg($k)
        set nr  $f_un($k)
        set fn  $f_fn($k)
        if {$key eq ""} { continue };   # invalid or disabled filter rules
        _dbx 4 " .$key /$rex/"
        grid [entry   $this.k$k -textvariable f_key($k) -width  8] \
             [radiobutton $this.x$k -variable f_mod($k) -value "-regexp"] \
             [radiobutton $this.e$k -variable f_mod($k) -value "-exact" ] \
             [entry   $this.l$k -textvariable f_len($k) -width  3] \
             [entry   $this.r$k -textvariable f_rex($k) ] \
             [entry   $this.f$k -textvariable f_fg($k)  -width 10] \
             [entry   $this.b$k -textvariable f_bg($k)  -width 10] \
             [entry   $this.s$k -textvariable f_fn($k)  -width 10] \
             [checkbutton $this.u$k -variable f_un($k)           ] \

        grid config $this.k$k $this.r$k -sticky ew
        grid config $this.f$k $this.b$k $this.s$k -sticky w
        guitip_set  $this.k$k $f_cmt($k)
        guitip_set  $this.r$k $f_cmt($k)
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
    grid columnconfigure $this {0 1 2 3 5 6 7 8} -weight 0
    grid columnconfigure $this 4   -minsize 20   -weight 1; # minsize does not work
    return $this
}; # create_filtertext

proc create_filtertable {parent cmd}    {
    #? create scrollable table widget with filter data
    #################### experimental, not yet ready #################
    ##### table ok, but missing:
    #####    radiobutton for column r und e ; probaly needs to use checkbutton
    #####    set variablen in all columns
    #####    changing font or colour must adapt cell in column 0
    #####    Tooltip
    #
    _dbx 2 "{$parent, $cmd}"
    global cfg
    global f_key f_mod f_len f_bg f_fg f_rex f_un f_fn f_cmt; # filters
    set this $parent
    font create osaftBig    {*}[font config TkFixedFont] -size 9
    pack [scrollbar $this.x -orient horizontal -command [list $this.t xview]] -side bottom -fill x
    pack [scrollbar $this.y -orient vertical   -command [list $this.t yview]] -side right  -fill y
    pack [tablelist::tablelist $this.t   \
             -exportselection true \
             -selectmode    extended  \
             -selecttype    cell   \
             -arrowcolor    black  \
             -background    white  \
             -borderwidth   2     \
             -stripebackground #e7e7e7 \
             -arrowstyle    $cfg(tfont) \
             -labelrelief   solid   \
             -labelfont     osaftBold \
             -labelpady     3     \
             -labelcommand  tablelist::sortByColumn -showarrow true \
             -movablecolumns true  \
             -movablerows    false \
             -showseparators true  \
             -xscrollcommand [list $this.x set] \
             -yscrollcommand [list $this.y set] \
             -font  osaftBig \
             -spacing 1 \
             -height 16 \
             -width 150 \
             -stretch 4 \
         ] -side left -fill both -expand yes
    # insert header line
    set head [list f_key f_moder f_modee f_chars f_regex f_fg f_bg f_font f_u ]
    foreach f $head { lappend titles 0 [_get_tipp $f] }
# TODO: -tooltipaddcommand,
    $this.t config -columns $titles
    $this.t columnconfigure 0 -width  10;#
    $this.t columnconfigure 7 -width  10;#
    # insert lines
    set row -1
    foreach {k key} [array get f_key] { # set all filter lines
        if {$k eq 0} { continue };
        incr row
        #set key $f_key($k)
        set key [_str2obj [string trim $key]]
        set mod $f_mod($k)
        set len $f_len($k)
        set rex $f_rex($k)
        set fg  $f_fg($k)
        set bg  $f_bg($k)
        set nr  $f_un($k)
        set fn  $f_fn($k)
        $parent.t insert end [list $f_key($k) r e $f_len($k) $f_rex($k) $f_fg($k) $f_bg($k) $f_fn($k) ]
        #				$f_mod($k $f_mod($k)

        foreach col [list 0 3 4 5 6 7] {
            $parent.t cellconfig $row,$col -editable yes -editwindow entry
        }
        $parent.t cellconfig $row,8    -editable yes -editwindow checkbutton
        $parent.t cellconfig $row,0 -fg $f_fg($k) -bg $f_bg($k) -font $f_fn($k)
    }
    return $this
}; # create_filtertable

proc create_filtertab   {parent cmd}    {
    #? create tab with filter data
    _dbx 2 "{$parent, $cmd}"
    global cfg
    pack [label $parent.text -relief flat -text [_get_tipp tabFILTER]]
    set this $parent.g
    pack [frame $this] -side top -expand yes -fill both
    set tab [create_filtertext  $this $cmd].t
    #if {"text"  eq $cfg(layout)} { set tab [create_filtertext  $this $cmd].t }
    #if {"table" eq $cfg(layout)} { set tab [create_filtertable $this $cmd].t }
        # create_filter_* returns widget, which is same as $parent
    catch { # silently ignore if systems has no fontchooser (i.e. Mac OS X)
        tk fontchooser config -command {create_selected "Font"}; # what to do with selection
            # there is no tk_fontchooser, but tk::fontchooser or tk fontchooser
        pack [button $parent.tkfont  -command {tk fontchooser show}] -side right
        guitheme_set $parent.tkfont $cfg(bstyle)
    }
    pack [button $parent.tkcolor -command {create_selected "Color" [tk_chooseColor]} ] -side right
    guitheme_set $parent.tkcolor $cfg(bstyle)
    return
}; # create_filtertab

proc create_filter      {parent cmd}    {
    #? create new window with filter commands for exec results; store widget in cfg(winF)
    _dbx 2 "{$parent, $cmd}"
    global cfg f_key f_bg f_fg f_cmt filter_bool myX
    if {[winfo exists $cfg(winF)]}  { show_window $cfg(winF); return; }
    set obj $parent;    # we want to have a short variable name
    set geo [split [winfo geometry .] {x+-}]
    set myX(geoF) +[expr [lindex $geo 2] + [lindex $geo 0]]+[expr [lindex $geo 3]+100]
        # calculate new position: x(parent)+width(parent), y(parent)+100
        # most window managers are clever enough to position window
        # correctly if calculation is outside visible (screen) frame
    set cfg(winF) [create_window "Filter:$cmd" $myX(geoF)]
        # FIXME: only one variable for windows, need a variable for each window
        #        workaround see osaft_exec
    set this $cfg(winF)
    _dbx 2 " parent: $obj | $cmd | $myX(geoF)"
    pack [frame $this.f -relief sunken -borderwidth 1] -fill x
    pack [label $this.f.t -relief flat -text [_get_text c_toggle]] -fill x
    pack [checkbutton $this.f.c -text [_get_text hideline] -variable filter_bool($obj,line)] -anchor w;
    guitip_set $this.f.c [_get_tipp hideline]
    gui_set_readonly $this.f.c
    foreach {k key} [array get f_key] {
        if {$k eq 0} { continue };
        #set key $f_key($k)
        set bg $f_bg($k)
        set fg $f_fg($k)
        set key [_str2obj [string trim $key]]
        set filter_bool($obj,HELP-$key) 1;  # default: text is visible
        pack [checkbutton $this.x$key \
                    -text $f_key($k) -variable filter_bool($obj,HELP-$key) \
                    -command "toggle_filter $obj HELP-$key \$filter_bool($obj,HELP-$key) \$filter_bool($obj,line);" \
             ] -anchor w ;
        # note: using $f_key($k) instead of $key as text
        # note: checkbutton value passed as reference
        # TODO: following "-fg white" makes check in checkbox invisible
        if {$fg ne ""}  { $this.x$key config -fg $fg }; # Tk is picky ..
        if {$bg ne ""}  { $this.x$key config -bg $bg }; # empty colour not allowd
        guitip_set $this.x$key "[_get_tipp show_hide] $f_cmt($k)";
    }
    return
}; # create_filter

proc create_about {}     {
    #? create new window with About text; store widget in cfg(winA)
    #  Show the text starting with  #?  from this file.
    _dbx 2 "{}"
    global cfg myX
    if {[winfo exists $cfg(winA)]}  { show_window $cfg(winA); return; }
    set cfg(winA) [create_window "About" $myX(geoA)]
    set txt [create_text $cfg(winA) [osaft_about "ABOUT"]].t
    $txt config -bg [_get_color osaft]

    # search for section headers and mark them bold
    set anf [$txt search -regexp -nolinestop -all -count end {^ *[A-ZÄÖÜß ]+$} 1.0]
    set i 0
    foreach a $anf {
        set e [lindex $end $i];
        $txt tag add sektion  $a "$a + $e char"
        incr i
    }
    $txt tag config sektion -font osaftBold

    # bind buttons and keys
    bind_browser $txt ABOUT-URL
    bind  $txt <KeyPress>   "search_view $txt %K"
    return
}; # create_about

proc create_pod   {sect} {
    #? create new window with complete help using external viewer
    # for advantages and disadvantages please see contrib/.o-saft.tcl
    global cfg myX prg
    # TODO: does probably not working on Windows
    #tk_messageBox -icon warning -title " using $prg(TKPOD)" \
    #    -message "$prg(TKPOD) will not be closed with $cfg(ICH)"
    putv  " exec {*}$prg(TKPOD) o-saft.pod -geo $myX(geoO) & "
    catch { exec {*}$prg(TKPOD) o-saft.pod -geo $myX(geoO) & };
    return
}; # create_pod

proc create_help  {sect} {
    #? create new window with complete help text; store widget in cfg(winO)
    #? if  sect  is given, jump to this section

    _dbx 2 "{$sect}"
    global cfg myX prg search

    if {[info exists prg(TKPOD)]==1} {
        if {$prg(TKPOD) ne "O-Saft"} {  # external viewer specified, use it ...
            create_pod $sect ;
            return;
        }
    }

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
    #
    # TODO: some section lines are not detected properly and hence missing

    _dbx 4 " 1. build help window"
    if {[winfo exists $cfg(winO)]} {    # if there is a window, just jump to text
        wm deiconify $cfg(winO)
        set name [_str2obj [string trim $sect]]
        search_show $cfg(winO).t "HELP-HEAD-$name"
        return
    }
    set this    [create_window {Help} $myX(geoO)]
    set txt     [create_text $this $cfg(HELP)].t;        # $txt is a widget here
    set toc     {}

    _dbx 4 " 2. add additional buttons for search"
    pack [button $this.f1.help_home -command "search_show $txt {HELP-LNK-T}; set search(curr) 0;"] \
         [button $this.f1.help_prev -command "search_next $txt {-}"] \
         [button $this.f1.help_next -command "search_next $txt {+}"] \
        [spinbox $this.f1.s -textvariable search(text) -values $search(list) \
             -command "search_list %d"   -wrap 1 -width 25 ] \
        [spinbox $this.f1.m -textvariable search(mode) -values [list exact regex smart fuzzy] \
             -command {global search; set search(last) ""} ] \
         [button $this.f1.helpreset -command "search_rset" ] \
         [button $this.f1.help_help -command {global cfg; create_about; $cfg(winA).t see 84.0} ] \
        -side left
        # TODO: remove hardcoded text position 84.0 in About
        # changing the search(mode) resets search(last) to ensure search execution
    $this.f1.m config -state readonly -relief groove -wrap 1 -width 5
    pack config  $this.f1.m  -padx 10
    pack config  $this.f1.help_home   $this.f1.help_help -padx $myX(rpad)
    guitheme_set $this.f1.help_home   $cfg(bstyle)
    guitheme_set $this.f1.help_prev   $cfg(bstyle)
    guitheme_set $this.f1.help_next   $cfg(bstyle)
    guitheme_set $this.f1.help_help   $cfg(bstyle)
    guitheme_set $this.f1.helpreset   $cfg(bstyle)
    guitip_set   $this.f1.m [_get_tipp help_mode]
    guitip_set   $this.f1.s [_get_tipp helpsearch]
    #guitip_set   $this.f1.help.rset  [_get_tipp helpreset]
    bind         $this.f1.s <Return> "
           global search
           if {\$search(last) != \$search(text)} {
               lappend search(list) \$search(text);
               incr    search(curr)
           };
           search_text $txt \$search(text);
           "

    _dbx 4 " 3. search for section head lines, mark them and add (prefix) to text"
    set anf [$txt search -regexp -nolinestop -all -count end {^ {0,5}[A-Z][A-Za-z_? '()=+,:.-]+$} 1.0]
    #dbx# puts "3. $anf\n$end"
    set i 0
    foreach a $anf {
        set e [lindex $end $i];
        set t [$txt get $a "$a + $e c"]        ;# don't trim, need leading spaces
        set l [string length $t]
        incr i
        _dbx 4 " 3. HEAD: $i\t$t"
        if {[_notTOC $t]} { continue; }         ;# skip some special strings
        if {[string trim $t] eq ""} { continue };# skip empty entries
        if {[regexp {^[A-Z]} $t]} { set toc "$toc\n" };  # add empty line for top level headlines
        set toc "$toc\n  $t"                   ;# prefix headline with spaces in TOC
        set name [_str2obj [string trim $t]]
        $txt tag add    HELP-HEAD       $a "$a + $e c"
        $txt tag add    HELP-HEAD-$name $a "$a + $e c"
    }
    $txt config -state normal
    $txt insert 1.0 "\nCONTENT\n$toc\n"
    $txt tag     add    HELP-LNK    2.0 2.7    ;# add markup
    $txt tag     add    HELP-LNK-T  2.0 2.7    ;#
    gui_set_readonly $txt
    #_dbx 4 "TOC:[$txt get 1.0 end]";
    set nam [$txt search -regexp -nolinestop {^NAME$} 1.0]; # only new insert TOC
    if {$nam eq ""} {
        _dbx 4 " 3. no text available"         ;# avoid Tcl errors
        return;
    };

    _dbx 4 " 4. search for all references to section head lines in TOC and add click event"
    # NOTE: used regex must be similar to the one used in 1. above !!
    set anf [$txt search -regexp -nolinestop -all -count end { *[A-Za-z_? '()=,:.-]+( |$)} 3.0 $nam]
    #dbx# puts "4. $anf\n$end"
    set i 0
    foreach a $anf {
        set e [lindex $end $i];
        set t [$txt get $a "$a + $e c"];
        incr i
        _dbx 4 " 4. TOC: $i\t$t"
        if {[regexp { - } $t]}  { continue }   ;# skip glossar lines
        if {[_notTOC $t]}       { continue }   ;# skip some special strings
        set name [_str2obj [string trim $t]]
        set b [$txt search -regexp {[A-Z]+} $a]
        $txt tag add    HELP-TOC    $b "$b + $e c" ;# do not markup leading spaces
        $txt tag add    HELP-TOC-$i $a "$a + $e c" ;# but complete line is clickable
        $txt tag bind   HELP-TOC-$i <ButtonPress> "search_show $txt {HELP-HEAD-$name}"
    }

    # 4a. search for all references to section head in text
        # only search words with all upper case characters and preceeded by 2 spaces
    set anf [$txt search -regexp -nolinestop -all -count end {  [A-Z]{4}[A-Z -]+ } $nam]
    #dbx# puts "4.a $anf\n$end"
    set i 0
    foreach a $anf {
        set e [lindex $end $i];
        set t [$txt get $a "$a + $e c"];
        incr i
        _dbx 4 " 4a. REF: $i\t$t"
        if {[regexp {^[A-Z]+} $t]} { continue };# skip headlines itself
        if {[regexp { - } $t]}     { continue };# skip glossar lines
        if {[_notTOC $t]}          { continue };# skip some special strings
        set name [_str2obj [string trim $t]]
        $txt tag add    HELP-REF-$i $a "$a + $e c"
        $txt tag bind   HELP-REF-$i <ButtonPress> "search_show $txt {HELP-HEAD-$name}"
    }

    _dbx 4 " 5. search all commands and options and try to set click event"
    set anf [$txt search -regexp -nolinestop -all -count end { [-+]-?[a-zA-Z0-9_=+-]+([, ]|$)} 3.0]
    #dbx# puts "4. $anf\n$end"
    # Loop over all matches.  The difficulty is to distinguish matches,  which
    # are the head lines like:
    #   --v
    #   +version
    # and those inside the text, like:
    #   ... option  --v  is used for ...
    # The rules for head lines are:
    #   start with spaces followed by + or - followed by word 'til end of line
    # Anything else is most likely a reference, but there are exceptions like:
    #   --v --v
    # is a head line, and following might be a reference:
    #   +version.
    # Unfortunately  --v  --v   (and similar examples) will not be detected as
    # head line. This is due to the regex in "text search ...",  which doesn't
    # allow spaces. # FIXME:

    set i 0
    foreach a $anf {
        set e [lindex $end $i];
        set l [$txt get "$a - 2 c" "$a + $e c + 1 c"];  # one char more, so we can detect head line
        set t [string trim [$txt get $a "$a + $e c"]];
        set r [regsub {[+]} $t {\\+}];  # need to escape +
        set r [regsub {[-]} $r {\\-}];  # need to escape -
        set name [_str2obj [string trim $t]]
        _dbx 4 " 5. LNK: $i\tHELP-LNK-$name\t$t"
        if {[regexp -lineanchor "\\s\\s+$r$" $l]} {     # FIXME: does not match all lines proper
            # these matches are assumed to be the header lines
            $txt tag add    HELP-LNK-$name $a "$a + $e c";
            $txt tag add    HELP-LNK       $a "$a + $e c";
        } else {
            # these matches are assumed references
            $txt tag add    HELP-LNK-$i $a "$a + $e c - 1 c"; # do not markup spaces
            $txt tag bind   HELP-LNK-$i <ButtonPress> "search_show $txt {HELP-LNK-$name}"
            $txt tag config HELP-LNK-$i -foreground [_get_color link]
            $txt tag config HELP-LNK-$i -font osaftSlant
        }
        incr i
    }

    _dbx 4 " 6. search for all examples and highlight them"
    # search $prg(rexCOMMANDS) if preceeded by at least 9 spaces, these spaces
    # must then be removed from the match, so they are not highlighted
    # FIXME: stiil matches some lines accidently, i.e. in  DEBUG  section
    set anf [$txt search -regexp -nolinestop -all -count end "^ \{9,\}$prg(rexCOMMANDS)\( \[^\\n\]+|$\)" 3.0]
    #dbx# puts "6. $anf\n$end"
    set i 0
    foreach a $anf {
        set e [lindex $end $i];
        set t [$txt get $a "$a + $e c"]
        _dbx 4 " 6. CODE: $i\tHELP-CODE\t$t"
        set s 10
        regexp {^ *} $t spaces                 ;# get count of leading spaces
        set s [string length $spaces]
        $txt tag add    HELP-CODE "$a + $s c" "$a + $e c";# start highlight at $s
        incr i
    }

    _dbx 4 " 7. search for all special quoted strings and highlight them"
    #dbx# puts "$txt\n[$txt get 0.0 end]"
    set anf [$txt search -regexp -all -count end {'[^']+'} 3.0]
    #dbx# puts "7. $anf\n$end"
    set i 0
    foreach a $anf {
        set e [expr [lindex $end $i] - 1]      ;# without trailing quote
        set t [$txt get "$a + 1 c" "$a + $e c"];# without leading  quote
        _dbx 4 " 7. CODE: $i\tHELP-CODE\t'$t'"   ;# add quotes in debug output
        $txt tag add    HELP-CODE $a "$a + $e c"
        $txt replace    $a         "$a + 1 c"        { }
        $txt replace   "$a + $e c" "$a + $e c + 1 c" { }
        incr i
    }

    _dbx 4 " 8. highlight all URLs and bind key"
    bind_browser $txt   HELP-URL

    # finally global markups
    $txt tag config     HELP-CODE -background [_get_color code]
    $txt tag config     HELP-URL  -foreground [_get_color link]
    $txt tag config     HELP-REF  -foreground [_get_color link]
    $txt tag config     HELP-TOC  -foreground [_get_color link]
    $txt tag config     HELP-TOC  -font osaftBold
    $txt tag config     HELP-LNK  -font osaftBold
    $txt tag config     HELP-HEAD -font osaftBold

    _dbx 4 " 9. MARK: [$txt mark names]"
    #_dbx 8 " TAGS: [$txt tag names]"; # huge output!!
    foreach tag [list HELP-TOC HELP-HEAD HELP-CODE HELP-URL HELP-LNK HELP-LNK-T HELP-search-pos] {
        _dbx 8 " $tag [llength [$txt tag ranges $tag]]:\t[$txt tag ranges $tag]"
        _dbx 8 "   TAG\t\t(start, end)\ttagged text"
        _dbx 8 " #---------------+---------------+------------------------"
        foreach {k l} [$txt tag ranges $tag] {
            set t [$txt get $k $l]
            # TODO: set rex "cipher"; if {[regexp $rex $t]} { _dbx 4 "   $tag:\t($k, $l)\t»$t«" }
            _dbx 8 "   $tag:\t($k, $l)\t»$t«"
        }
        _dbx 8 " #---------------+---------------+------------------------"
    }

    bind $txt <KeyPress>    "search_view $txt %K"
    #bind $txt <MouseWheel>  "search_view $txt %D" ;# done automatically

    set cfg(winO) $this
    if {$sect ne ""} {
        set name [_str2obj [string trim $sect]]
        search_show $cfg(winO).t "HELP-HEAD-$name"
    }
    return
}; # create_help

proc create_note  {parent title} {
    #? create notebook TAB; returns widget
    _dbx 2 "{$parent, »$title«}"
    set name [_str2obj $title]
    set this $parent.$name
    set alt  0
    if {[regexp {^\(} $title]} { set alt 1; };  # don't use (, but next charcter
    frame       $this
    $parent add $this  -text $title -underline $alt
    return $this
}; # create_note

proc create_tab   {parent layout cmd content} {
    #? create new TAB in .note and set focus for it; returns text widget in TAB
    _dbx 2 "{$parent, $layout, $cmd, ...}"
    _dbx 4 " content=»$content«"
    global cfg
    set tab [create_note $parent "($cfg(EXEC)) $cmd"];
    switch $layout {
        text    { set txt [create_text  $tab $content].t }
        table   { set txt [create_table $tab $content].t }
    }
        # ugly hardcoded .t from .note
    pack [button $tab.saveresult -command "osaft_save $txt {TAB} $cfg(EXEC)"] \
         [button $tab.ttyresult  -command "osaft_save $txt {TTY} $cfg(EXEC)"    ] \
         [button $tab.filter     -command "create_filter $txt $cmd"    ] \
         -side left
    pack [button $tab.closetab   -command "destroy $tab"] -side right
    guitheme_set $tab.closetab   $cfg(bstyle)
    guitheme_set $tab.saveresult $cfg(bstyle)
    guitheme_set $tab.ttyresult  $cfg(bstyle)
    guitheme_set $tab.filter     $cfg(bstyle)
    $cfg(objT) select $tab
    return $txt
}; # create_tab

proc create_cmd   {parent title} {
    #? create button to run O-Saft command; returns widget
    _dbx 2 "{$parent, »$title«}"
    global cfg
    set name [regsub {^\+} $title {cmd}];   # keys start with cmd instead of +
    set this $parent.$name
    pack [button $this -text $title -command "osaft_exec $parent $title"] -side left
    guitheme_set $this $cfg(bstyle)
    return $this
}; # create_cmd

proc create_opt   {parent title} {
    #? create checkbutton for O-Saft options; returns widget
    _dbx 2 "{$parent, »$title«}"
    global cfg
    set name [regsub {^--} $title {cmd}];   # keys start with cmd instead of +
    set this $parent.$name
    pack [checkbutton $this -text $title -variable cfg($title)] -side left -padx 5
    guitip_set   $this [_get_tipp $title]
    return $this
}; # create_opt

proc create_win   {parent title cmd} {
    #? create window for commands and options
    #  creates one button for each line returned by: o-saft.pl --help=opt|commands
    # title must be string of group of command or options
    _dbx 2 "{$parent, »$title« $cmd}"
    global cfg myX prg
    set this $parent
    set win  $this
    set max  2     ;# OPT: 3 columns 0..2; CMD: 4 columns
    switch $cmd {
      "CMD" { set data $cfg(CMDS); incr max }
      "OPT" { set data $cfg(OPTS) }
      default { pwarn "create_win called with wrong command »$cmd«"; return }
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
        # SEE Help:Syntax in o-saft-man.pm and
        # also  OSaft/Doc/Data.pm  and  OSaft/Doc/help.txt
        # Note that "Discrete Commands ..." in cfg(HELP) are missing and have
        # no description; must use that from cfg(CMDS).

    set last_key "";# remember last option
    set last_obj "";# remember last entry widget
    set values   {};# collected values of last option
    set skip 1     ;# skip data until $title found
    foreach l [split $data "\r\n"] {
        set dat [string trim $l]
        if {[regexp $prg(rexOUT-cmd) $dat]} { set skip 1; };# next group starts
        if {"$title" eq "$dat"} {   # FIXME: scary comparsion, better use RegEx
            # title matches: create a window for checkboxes and entries
            set skip 0;
            _dbx 4 " create window: $win »$dat«"
            set dat [string toupper [string trim $dat ] 0 0]
            set win [create_window $dat ""]
            if {$win eq ""} { return; }    ;# do nothing, even no: show_window $this;
            set this $win.g
            frame $this;    # frame for grid
            continue
        }
        if {$skip==1}                        { continue; }
        #dbx# puts "DATA $dat"
        # skipped general
        if {$dat eq ""}                      { continue; }
        if {[regexp $prg(rexOUT-head) $dat]} { continue; } ;# ignore header lines
        # skipped commands
        if {[regexp $prg(rexCMD-int)  $dat]} { continue; } ;# internal use only
        # skipped options
       #if {"OPTIONS" eq $dat}               { continue; }
        if {[regexp $prg(rexOPT-help) $dat]} { continue; }
        if {[regexp $prg(rexOUT-int)  $dat]} { continue; } ;# use other tools for that

        # the line $l looks like:
        #    our_key   some descriptive text
        # where $dat should contain "our_key" and $tip "some descriptive text"
        # so all multiple white spaces are reduced, which results in first word
        # being $dat and all the rest will be $tip
        # multiple white spaces in descriptive text are lost, that's ok if any
        set dat [regsub -all {\s+}    $dat { }]
        set tip [regsub {[^\s]+\s*}   $dat {} ]
        set dat [lindex [split $dat " "] 0]

        _dbx 4 " verify: »$dat«\t$cmd"
        set name [_str2obj $dat]
        if {[winfo exists $this.$name]} {
            # this occour if command/or option appears more than once in list
            # hence the warning is visible only in verbose mode
            putv "**WARNING: create_win exists: $this.$name; ignored"
            continue
        }
        frame $this.$name              ;# create frame for command' or options' checkbutton
# # pack [button $this.$name.h -text {?} -command "create_help {$dat}" -borderwidth 1] -side left
        if {[regexp {=} $dat]==0} {
            #dbx# puts "create_win: check: $this.$name.c -variable cfg($dat)"
            pack [checkbutton $this.$name.c -text $dat -variable cfg($dat)]  -side left -anchor w -fill x
        } else {
            regexp $prg(rexOPT-cfg) $l dumm idx val    ;# --idx=val --> --idx val
            if {$last_key eq $idx} { lappend values $val; continue };# ignore repeated options, but keep value
            if {[winfo exists $last_obj]} {
                set txt "<text>"
                if {[llength $values] > 0} { set txt [join $values { | }]; }
                guitip_set $last_obj "possible values: $txt"   ;# $tip may containing collected values
            }
            _dbx 4 " create: »$idx« »$val«"
            #dbx# puts "create_win: entry: $this.$name.e -variable cfg($idx)"
            pack [label  $this.$name.l -text $idx -width $myX(lenl)] -fill x -side left -anchor w
            pack [entry  $this.$name.e -textvariable cfg($idx)]      -fill x -side left -expand 1
            set last_obj $this.$name.e
            set last_key $idx
            set values {}
            if {[regexp {^[a-z]*$} $l]} { set cfg($idx) $val }   ;# only set if all lower case
            $this.$name.l config -font TkDefaultFont   ;# reset to default as Label is bold
        }
        grid $this.$name -sticky w
        guitip_set $this.$name "$tip"  ;# $tip may be empty, i.e. for options
        # TODO: create tooltip with $values for very last $this.$name.e
    }
    pack $this -fill both -expand 1    ;# delayed pac for better performance

    # now arrange grid in rows and columns
    # idea: arrange widgets in at least 3 columns
    #       we can use 4 columns in Commands window because widgets are smaller
    # sorting is vertical (horizontal sorting commented out)
    set slaves [lsort -nocase [grid slaves $this]]
    set cnt [llength $slaves]
    if {$cnt < 1} { return }   ;# avoid math errors, no need to resize window
    set rows [expr $cnt / [expr $max + 1]]
    _dbx 2 " cnt/(max+1) = rows: $cnt/($max+1) = $rows"
    set col 0
    set row 0
    foreach slave $slaves {
        #if {$col > $max} { incr row; set col 0 };  # horizontal sorting
        if {$row > $rows} { incr col; set row 0 };  # vertical sorting

        grid config $slave -row $row -column $col -padx 8
        #incr col;   # horizontal
        incr row;   # vertical
    }
    return
}; # create_win

proc create_buttons {parent cmd} {
    #? create buttons to open window with commands or options
    #  creates one button for header line returned by: o-saft.pl --help=opt|commands
    #  cmd must be "OPT" or "CMD"
    _dbx 2 "{$parent, $cmd}"
    global cfg prg
    set data $cfg(OPTS)
    set txt  [_get_tipp "tab$cmd"];      # tabCMD and tabOPT
    switch $cmd {
      "CMD" { # expected format of data in $cfg(CMDS) and $cfg(OPTS) see create_win() above
              set data $cfg(CMDS) }
      "OPT" { # add options for o-saft.tcl itself
              pack [frame $parent.of] -fill x -padx 5 -anchor w
              pack [label $parent.of.l -text "Layout format of results:"] \
                   [radiobutton $parent.of.t$cmd -variable cfg(layout) -value "table" -text "table"] \
                   [radiobutton $parent.of.s$cmd -variable cfg(layout) -value "text"  -text "text"] \
                   -padx 5 -anchor w -side left
              guitip_set $parent.of [_get_tipp "layout"]
            }
      default { pwarn "create_buttons called with wrong command »$cmd«"; return }
    }
    #_dbx 4 "$data";
    pack [label  $parent.o$cmd -text $txt ] -fill x -padx 5 -anchor w -side top
    foreach l [split $data "\r\n"] {
        set txt [string trim $l]
        if {[regexp $prg(rexOUT-cmd)  $txt] == 0} { continue }  ;# buttons for Commands and Options only
        if {[regexp $prg(rexOUT-hide) $txt] != 0} { continue }  ;# we do not support these options in the GUI
        # skipped general
        if {$txt eq ""}                      { continue; }
        if {[regexp $prg(rexOUT-head) $txt]} { continue; }; # header or Warning
        if {"OPTIONS" eq $txt}               { continue; }
        # remove noicy prefix and make first character upper case
        set dat  [string toupper [string trim [regsub {^(Commands|Options) (to|for)} $txt ""]] 0 0]
        set name [_str2obj $txt]
        set this $parent.$name
        _dbx 4 " .$name {$txt}"
        pack [frame $this] -anchor c -padx 10 -pady 2
        pack [button $this.b -text $dat -width 58 -command "create_win .$name {$txt} $cmd" -bg [_get_color button] ] \
             [button $this.help_me -command "create_help {$txt}" ] \
               -side left
        guitheme_set $this.help_me $cfg(bstyle)
        guitip_set   $this.b [_get_tipp settings]

        # argh, some command sections are missing in HELP, then disable help button
        if {[regexp $prg(rexOUT-show) $txt] == 1} { $this.help_me config -state disable }
    }
    return
}; # create_buttons

proc create_main  {targets} {
    #? create main window (the complete GUI)
    #| main {
    _dbx 2 "{»$targets«}"
    global cfg prg myX hosts
    set w ""
    pack [frame $w.ft0]; # create dummy frame to keep create_host() happy

    #| create command buttons for simple commands and help
    pack [frame     $w.fq] -fill x -side bottom
    pack [button    $w.fq.closeme  -command {exit}] -side right -padx $myX(rpad)
    if {$cfg(VERB)==1} {
        #pack [button $w.fq.r -text "o"  -command "open \"| $argv0\"; exit" ] -side right
        # TODO: does not work proper 'cause passing --v fails

        pack [checkbutton $w.fq.img_txt -variable cfg(img_txt) -command {
            if {$cfg(img_txt)==1} { set cfg(bstyle) "image" }
            if {$cfg(img_txt)==0} { set cfg(bstyle) "text"  }
            _dbx 4 " toggle: $cfg(img_txt) # $cfg(bstyle) "
            guitheme_init $cfg(bstyle)
        } \
        ] -side right
        if {$cfg(bstyle) eq "image"} { $w.fq.img_txt select }
        guitheme_set $w.fq.img_txt $cfg(bstyle)
    }
    pack [frame     $w.fc] -fill x
    pack [button    $w.fc.cmdstart -command "osaft_exec $w.fc {Start}"] -side left -padx 11
    foreach b $prg(Ocmd) {
        create_cmd  $w.fc $b;
    }
    pack [button    $w.fc.loadresult -command "osaft_load {Load}"] -side left -padx 11
    pack [button    $w.fc.help -command "create_help {}"] -side right -padx $myX(padx)

    #| create option buttons for simple access
    pack [frame     $w.fo] -fill x
    pack [label     $w.fo.ol -text " "] -side left -padx 11
    foreach b $prg(Oopt) {
        create_opt  $w.fo $b;
    }
    if {[regexp {\-docker$} $prg(SAFT)]} {
        pack [entry $w.fo.dockerid -textvariable prg(docker-id) -width 12] -anchor w
        guitip_set  $w.fo.dockerid [_get_tipp docker-id]
    }

    #| create notebook object and set up Ctrl+Tab traversal
    set cfg(objT)   $w.note
    ttk::notebook   $cfg(objT) -padding 5
    ttk::notebook::enableTraversal $cfg(objT)
    pack $cfg(objT) -fill both -expand 1

    #| create TABs: Command and Options
    set tab_cmds    [create_note $cfg(objT) "Commands"]
    set tab_opts    [create_note $cfg(objT) "Options"]
    set tab_filt    [create_note $cfg(objT) "Filter"]
    set cfg(EXEC) 2;# ttk::notebook's index counting starts at 0
    create_buttons  $tab_cmds {CMD}    ;# fill Commands pane
    create_buttons  $tab_opts {OPT}    ;# fill Options pane
    create_filtertab $tab_filt {FIL}   ;# fill Filter pane

    #| add Save and Reset button in Options pane
    pack [button    $tab_opts.saveresult -command {osaft_save "CFG" 0}      ] -side left
    pack [button    $tab_opts.reset      -command {osaft_reset; osaft_init;}] -side left
    osaft_init;     # initialise options from .-osaft.pl (values shown in Options tab)

    #| create status line
    pack [frame     $w.fl   -relief sunken -borderwidth 1] -fill x
    pack [text      $w.fl.t -relief flat   -height 3 -background [_get_color status] ] -fill x
    set cfg(objS)   $w.fl.t
    gui_set_readonly $cfg(objS)

    #| add hosts from command line
    foreach host $targets {         # display hosts
        if {$hosts(0) > 5} { pwarn "only 6 hosts possible; »$host« ignored"; continue };
        create_host $w
        set hosts($hosts(0)) $host
    }

    #| add one Host: line  with  +  and  !  button
    create_host $w

    #| apply themes
    guitheme_init $cfg(bstyle)
    #| main }

    return
}; # create_main

proc search_view  {w key}   {
    #? scroll given text widget according key
    _dbx 2 "{$w, $key}"
    #dbx puts "search_view: {$w, $key} [$w yview]"
    # Up and Down are handled automatically, usually, but not always, grrrr
    switch $key {
        Home    { $w see [$w index HELP-LNK-T.first] }
        Prior   { $w yview scroll -1  pages }
        Up      { $w yview scroll -1  units }
        Down    { $w yview scroll  1  units }
        Next    { $w yview scroll  1  pages }
        End     { $w see [$w index HELP-HEAD-oAUTHOR.first] }
    }
    # FIXME: Home and End not working (reason Tk's default binding)
    # tested: "$w yview end", "$w yview scroll 1.0", "$w yview moveto 1.0", "$w see 1.0"
    #   Home    { $w yview scroll -99 pages }
    #   End     { $w yview scroll  99 pages }
    return
}; # search_view

proc search_show  {w mark}  {
    #? jump to mark in given text widget
    _dbx 2 "{$w, $mark}"
    catch { $w see [$w index $mark.first] } err
    if {$err eq ""} {
        # "see" sometimes places text to far on top, so we scroll up one line
        $w yview scroll -1 units
    } else {
        _dbx 4  " err    = $err"
    }
    return
}; # search_show

proc search_mark  {w see}   {
    #? remove previous highlight, highlight at position see
    _dbx 2 "{$w, $see}"
    set anf  [lindex $see 0]
    set end  [lindex $see 1]
    # $see contains tuple with start and end position of matched text, now
    # find complete surounding paragraph, a paragraph is enclosed in  \n\n
    set box_anf [$w search -backward -regexp {\n\s*\n} $anf]
    set box_end [$w search -forward  -regexp {\n\s*\n} $end]
    _dbx 4 " box_anf= $box_anf\tanf= $anf\tend= $end\tbox_end= $box_end"
    $w tag delete HELP-search-box  $anf
    $w tag add    HELP-search-box "$box_anf + 2 c" "$box_end + 1 c"
    $w tag config HELP-search-box  -relief raised -borderwidth 1 -background [_get_color osaft]
    $w tag delete HELP-search-mark $anf
    $w tag add    HELP-search-mark $anf $end
    $w tag config HELP-search-mark -font osaftBold -background yellow
    return
}; # search_mark

proc search_more  {w search_text regex} {
    #? show overview of search results in new window
    # $w is the widget with O-Saft's help text, all matched texts are already
    # listed in $w's tag HELP-search-pos, each match is a tuple consisting of
    # start and end position (index)
    _dbx 2 "{$w, »$search_text«, $regex}"
    global search myX
    set matches [$w tag ranges HELP-search-pos];# get all match positions
    set cnt  [_count_tuples $matches]
    set this [create_window "$cnt matches for: »$regex«" $myX(geoo)]
    set txt  [create_text $this ""].t
    #{ adjust window, quick&dirty
    create_window:title   $this "Search Results for: »$search_text«"
    create_window:nosave  $this    ;# no "Save" button needed here
    create_window:helpcmd $this {create_about; global cfg; $cfg(winA).t see 84.0}
        # redefine help button to show About and scroll to Help description
    #}
    $txt config -state normal
    #_dbx 4 " HELP-search-pos ([llength $matches]): $matches"
    set i 0
    while {$i < [llength $matches]} {
        # Note: $anf and $end are positions in the window of $W
        #       $tag_anf and $tag_end are positions in this window
        set anf [lindex $matches $i]; incr i;
        set end [lindex $matches $i]; incr i;
        # compute surounding lines and insert in new window
        set box_anf [$w search -backward -regexp {\n\s*\n} $anf]
        set box_end [$w search -forward  -regexp {\n\s*\n} $end]
        set tag_anf [$txt index end]
        $txt insert end [$w get  $box_anf $box_end]
        set tag_end [$txt index end]
        # build tag for extracted text
        $txt tag add    TAG-$i  "$tag_anf + 1 char" "$tag_end - 1 char"
        $txt tag config TAG-$i  -relief raised -borderwidth 1
        # bind events to highlight text
        $txt tag bind   TAG-$i  <Any-Enter>  "$txt tag config TAG-$i -background [_get_color osaft]"
        $txt tag bind   TAG-$i  <Any-Leave>  "$txt tag config TAG-$i -background white"
        $txt tag bind   TAG-$i <ButtonPress> "$w   see $anf; search_mark $w \"$anf $end\"";
        guitip_set $txt "[_get_tipp helpclick]"
        # TAG-$i  are never used again; new searches overwrite existing tags
    }
    gui_set_readonly $txt
    return $this
}; # search_more

proc search_next  {w direction} {
    #? show next search text in help window
    # direction: + to search forward, - to search backward
    global search
    _dbx 2 "{$w, $direction}"
    _dbx 4 " see    = $search(see)"
    # nextrange, prevrange return a tuple like:        23.32 23.37
    # HELP-search-pos contains something like: 2.1 2.7 23.32 23.37 42.23 42.28
    switch $direction {
      {+} { set see [$w tag nextrange HELP-search-pos [lindex $search(see) 1]] }
      {-} { set see [$w tag prevrange HELP-search-pos [lindex $search(see) 0]] }
    }
    if {$see eq ""} {
        # reached end of range, or range contains only one, switch to beginning
        set see [lrange [$w tag ranges HELP-search-pos] 0 1]   ;# get first two from list
        if {$see eq ""} { return };
        # FIXME: round robin for + but not for -
    }
    $w see [lindex $see 0]             ;# show at start of match
    search_mark $w "$see"
    #$w yview scroll 1 units           ;# somtimes necessary, but difficult to decide when
    set search(see)  $see
    return
}; # search_next

proc search_text  {w search_text} {
    #? search given text in help window's $w widget
    _dbx 2 "{$w, »$search_text«}"
    global search
    if {[regexp ^\\s*$ $search_text]}  { return; } ;# do not search for spaces
    if {"exact" ne $search(mode)} {
        if {[string length $search_text] < 4} {
            tk_messageBox -icon warning -title "Search pattern" -message [_get_text h_min4chars]
            return
        }
    }
    if {$search_text eq $search(last)} { search_next $w {+}; return; }
    # new text to be searched, initialize ...
    set search(last) $search_text
    $w tag delete HELP-search-pos      ;# tag which contains all matches
    _dbx 4 " mode           = $search(mode)"
    set regex $search_text
    set words ""       ;# will be computed below
    set rmode "-regexp";# mode (switch) for Tcl's "Text search"
    # prepare regex according smart and fuzzy mode; builds a new regex
    switch $search(mode) {
        {smart} {
            set regex [regsub -all {([(|*)])}   $regex {[\1]}] ;# some characters need to be escaped before building regex
            # build pattern with each char optional
            set i 0
            foreach c [lindex [split $regex ""]] {
                append words "|" [join [lreplace [split $regex ""] $i $i "$c?"] ""]
                incr i
            }
        }
        {fuzzy} {
            # some common synonyms, then each char as optional wildcard
            set regex [regsub -all {([(|*)])}   $regex {[\1]}]
            set regex [regsub -all -nocase {ou} $regex {o}]
            set regex [regsub -all -nocase {ph} $regex {f}]
            set regex [regsub -all -nocase {qu} $regex {q}]
            set regex [regsub -all -nocase {th} $regex {t}]
            # now build a pattern for each character position
            set i 0
            foreach c [lindex [split $regex ""]] {
                # only replace well known characters, leave meta as is
                if {[regexp {[A-Za-z0-9 _#'"$%&/;,-]} $c]} {
                    # "' quotes to balance those in $regex (keeps editor happy:)
                    set       replace {.?};
                    switch [string tolower $c] {
                      f { set replace {(?:ph|p|f)?} }
                      o { set replace {(?:ou|o)?}   }
                      q { set replace {(?:qu|q)?}   }
                      t { set replace {(?:th|t)?}   }
                    }
                    # [csz]? and [iy]? and [dt]? is handled by .?
                    append words "|" [join [lreplace [split $regex ""] $i $i $replace] ""]
                }
                incr i
            }
        }
        {regex} {
            # regex fails, when some meta characters are uses as first or last
            # character, sanatized regex to avoid compiling regex
            # Note: Tcl is picky about character classes, need \\ inside []
            set regex [regsub {^(\\)}     $regex {\\\1}]   ;# leading  \ is bad
            set regex [regsub {^([|*+-])} $regex {[\1]}]   ;# leading *|+ is bad
            set regex [regsub {([|])$}    $regex {[\1]}]   ;# trailing | is bad
            set regex [regsub {(\\)$}     $regex {\\\1}]   ;# trailing \ is bad
        }
    }
    if {"exact" ne $search(mode)} {
        # we have the original search_text as first alternate, and various
        # variants following in a non-capture group
        # Note: $words has already leading | hence missing in concatenation
        set regex "(?:$regex$words)"
    }
    _dbx 4 " regex ($search(mode))  = $regex";
    # now handle common mistakes and set mode (switch) for Tcl's "text search"
    switch $search(mode) {
        {exact} { set rmode "-exact" }
        {smart} -
        {fuzzy} -
        {regex} {
            # simply catch compile errors using a similar call as for matching
            _dbx 4 " regex #$search(mode)#  = $regex";
            set rmode "-regexp"
            set err ""
            catch { $w search -regexp -all -nocase -- $regex 1.0 } err
            if {[regexp {compile} $err]} {
                tk_messageBox -icon warning -title [_get_text h_badregex] -message $err
                return
            }
            # else { regex OK }
            }
    }
    _dbx 4 " regex sanatized= $regex";
    _dbx 4 " regex mode     = $rmode";
    # ready to fire ...
    set anf [$w search $rmode -all -nocase -count end -- $regex 1.0]
    if {"" eq $anf} {
        # Show warning if no matches found. This could simply be accomplished
        # using Tcl/Tk's tk_messageBox like:
        #   tk_messageBox -icon warning -title "Serach" -message "no matches"
        # but we don't want to bother the user to click a button to make this
        # message box disappear.  Instead we use our own toplevel window with
        # following adaptions:
        #   no "Save" button; "Help" button to show description for "Search"
        # finally, the window will be destroyed after a few seconds.
        global myX
        set warn [create_window "[_get_text h_nomatch] »$search_text«" $myX(geo-)]
        create_window:title   $warn "Search ..."
        create_window:nosave  $warn    ;# no "Save" button needed here
        create_window:helpcmd $warn {create_about; global cfg; $cfg(winA).t see 84.0}
        set   auto_destroy_timeout wait
        after 6000 set auto_destroy_timeout killme
        vwait auto_destroy_timeout
        destroy  $warn
        return
    }
    # got all matches, tag them
    set i 0
    foreach a $anf {                    # tag matches; store in HELP-search-pos
        set e [lindex $end $i];
        incr i
        $w tag add   HELP-search-pos $a  "$a + $e c"
        _dbx 4 " HELP-search-pos tag:  $a … $a + $e c"
    }
    set tags [$w tag ranges HELP-search-pos]
    _dbx 4 " HELP-search-pos: $tags"
    set search(see)  [lrange $tags 0 1];# remember current position
    $w tag config HELP-search-pos -background [_get_color osaft]
    search_mark $w $search(see)
    $w see [lindex $search(see) 0]
    _dbx 4 " see= $search(see)\tlast= $search(last)"
    # show window with all search results (note: $anf contains tuples)
    if {$search(more) < [_count_tuples $anf]} {
       search_more $w $search_text $regex
    }
    return
}; # search_text

proc search_rset  {} {
    #? reset/clear search list (history)
    _dbx 2 "{}"
    global search
    set search(curr) 0
    set search(list) ""
    set search(last) ""
    set search(see)  ""
    set search(text) "";# resets entry field
    return
}; # search_rset

proc search_list  {direction} {
    #? get next or previous search text from search list (history)
    _dbx 2 "{$direction}"
    global search
    set  len [llength $search(list)]
    switch $direction {
        {up}   { incr search(curr) +1 }
        {down} { incr search(curr) -1 }
    }
    if {$search(curr) < 0} { set search(curr) [expr $len - 1] }
    if {$search(curr) > [expr $len - 1]} { set search(curr) 0 }
    set search(text) [lindex $search(list) $search(curr)]
    _dbx 4 " curr= $search(curr) of $len, »$search(text)«"
    return
}; # search_list

proc osaft_write_rc     {}  {
    #? print data for resource file
    # print all lines between  RC-ANF and RC-END
    _dbx 2 "{}"
    global cfg argv0
    set qq {"} ;# dumm "
    if [catch { set fid [open $argv0 r]} err] { puts "**ERROR: $err"; exit 2 }
    # TODO: print docu, see contrib/.o-saft.tcl
    # $rc_doc is used to define help text with the same syntax as used for this
    # file to avoid that it will be extracted with  --help  option, the text is
    # defined with a leading space in each line.
    # Note that the VERSION of the generated file is the same as the VERSIOn of
    # this file itself.
    set rc_doc "#?
 #? NAME
 #?      .o-saft.tcl -  resource file for o-saft.tcl
 #?
 #? SYNOPSIS
 #?      source .o-saft.tcl
 #?
 #? DESCRIPTION
 #?      This is the user-configuration file for O-Saft's GUI  o-saft.tcl .
 #?
 #? USAGE
 #?      This file must recide in the user's  HOME  directory or the  directory
 #?      where  o-saft.tcl  will be started.
 #?
 #? SYNTAX
 #?      Content of this file must be valid Tcl syntax. Values may contain  Tcl
 #?      variables.
 #?
 #? VERSION
 #?      @(#) .o-saft.tcl generated by 1.226 19/10/03 10:14:32
 #?
 #? AUTHOR
 #?      dooh, who is author of this file? cultural, ethical, discussion ...
 #?
 # -----------------------------------------------------------------------------"
    puts "#!/bin/cat
[regsub -all -line {^ } $rc_doc ""]

set cfg(RCSID)  {1.7};  # initial SID, do not remove

package require Tcl 8.5

set cfg(TITLE)  {$cfg(TITLE)}"

    global cfg_colors cfg_texts cfg_tipps

    puts "\narray set cfg_color $qq"
    puts "    DESC\t{$cfg_colors(DESC)}"
    foreach key [lsort [array names cfg_colors]] {
        if {[regexp ^DESC $key]} { continue }
        puts "    $key\t{$cfg_colors($key)}"
    }
    puts "$qq;"

    puts "\narray set cfg_label $qq"
    puts "    DESC\t{$cfg_texts(DESC)}"
    foreach key [lsort [array names cfg_texts]] {
        if {[regexp ^DESC $key]} { continue }
        puts "    $key\t{$cfg_texts($key)}"
    }
    puts "$qq;"

    puts "\narray set cfg_tipp $qq"
    puts "    DESC\t{$cfg_tipps(DESC)}"
    foreach key [lsort [array names cfg_tipps]] {
        if {[regexp ^DESC $key]} { continue }
        puts "    $key\t{$cfg_tipps($key)}"
    }
    puts "$qq;"

    set skip 1
    foreach l [split [read $fid] "\r\n"] {
        if {[regexp {^# RC-ANF} $l]} { set skip 0; continue }
        if {[regexp {^# RC-END} $l]} { set skip 1; break    }
        if {$skip == 1} { continue }
        set l [regsub -all {\$0} $l $cfg(ICH)]
        puts $l
    }
    close $fid

    puts "
#-----------------------------------------------------------------------------{
#   Tcl's  option  command can be used here too, for example:
# option add *Button.font Bold;
# option add *Label.font  Bold;
# option add *Text.font   mono;
    # NOTE  that setting other fonts may change the layout of the GUI,  it may
    #       only be necessary to adapt some sizes (see myX) too.
#
# set prg(option) 1  ;# set to 1 to avoid internal 'option add ...' commands
    # To avoid  o-saft.tcl  using its private settings,  this variable must be
    # set to  1
#-----------------------------------------------------------------------------}
";

    return
}; # osaft_write_rc

proc osaft_write_opts   {}  {
    #? extract and print options from myself
    _dbx 2 "{}"
    global argv0
    set fid [open $argv0 r]
    set txt [read $fid]
    # The goal here is to extract all known options of this tool.  They are
    # found in  __ main __  where there is a  switch  statement.  All cases
    # there look like:
    #       --opt1 -
    #       --opt2 {
    #       --opt3 { some tcl code 
    #       +opt   {
    #       --d=*  {
    # If a line matches  ^\s*[+-]  it will be trimmed to remove leading and
    # trailing spaces, also all other saces are sqeezed to one space.  Then
    # it can be split at spaces,  which results in an array with the option
    # as first and  -  or  {  as second element.
    # The options  --*  and  +*  are ignored.
    # dummy line with }}}}} to keep Tcl parser happy
    foreach l [split $txt "\r\n"] {
        if {![regexp {^\s*[+-]}      $l]}   { continue; }
        if { [regexp {^\s*[+-]-?[*]} $l]}   { continue; }
        set cols [split [regsub -all {\s+} [string trim $l] " "] " "]
        set col2 [lindex $cols 1]
        if { "\{" eq $col2 || "-" eq $col2 } { puts [lindex $cols 0] }
    }
    close $fid
    return
}; # osaft_write_opts

proc osaft_about    {mode}  {
    #? extract description from myself; returns text
    _dbx 2 "{$mode}"
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

proc osaft_help   {}        {
    #? get help from o-saft.pl --help (for use in own help window)
    _dbx 2 "{}"
    global cfg prg
    # get information from O-Saft; it's a performance penulty, but simple ;-)
    putv               " exec {*}$prg(PERL) $prg(SAFT) [docker_args] +help "
    set help ""; catch { exec {*}$prg(PERL) $prg(SAFT) [docker_args] +help } help
    if {5 > [llength [split $help "\n"]]} {
        _dbx 2 " help = »$help«"
        # exec call failed, probably because  PATH  does not contain . then
        # prg(SAFT) returns an error, most likely just one line, like:
        #   couldn't execute "o-saft.pl": no such file or directory
        # as this message depends on the  lanuguage setting  of the calling
        # shell, we do not check for any specific string, but for more than
        # one line, means that $help must be more than one line
        # if it was a problem with docker, following most likely fails too
        # FIXME: workaround does not work with --docker
        set prg(SAFT) [file join "." $prg(SAFT)];# try current directory also
        putv               " exec {*}$prg(PERL) $prg(SAFT) [docker_args] --no-rc +help "
        set help ""; catch { exec {*}$prg(PERL) $prg(SAFT) [docker_args] --no-rc +help } help
    }

    _dbx 4 " 1. collect more documentations with --help=*"
    set info ""
    foreach key [list alias data checks regex rfc glossar] {
        # missing: text ourstr
        set txt ""
        putv  " exec {*}$prg(PERL) $prg(SAFT) --no-rc --help=$key "
        catch { exec {*}$prg(PERL) $prg(SAFT) --no-rc --help=$key } txt
        if {2 < [llength [split $txt "\n"]]} {
            set txt [regsub -all {[&]} $txt {\\&}] ;# avoid interpretation by regexp
            # add section header, hardcoded (stolen from o-saft-man.pm)
            switch $key {
              {alias}   { set head "Aliases for commands and options"
                          set txt [regsub -all -line {\n}  $txt "\n        "]
                        }
              {data}    { set head "Available commands for informations"
                          set txt [regsub -all -line {(\n)(\s*)}  $txt {\1        \2+}]
                          set txt [regsub {^(\s*)} $txt {\1        +}] ;# pretty print
                              # each key (left) is a command, hence add +
                        }
              {checks}  { set head "Available commands for checks"
                          set txt [regsub -all -line {(\n)(\s*)}  $txt {\1        \2+}]
                          set txt [regsub {^(\s*)} $txt {\1        +}] ;# pretty print
                              # each key (left) is a command, hence add +
                        }
              {regex}   { set head "Regular expressions used internally"
                          set txt [regsub -all -line {(\n)(\s*)([^ ]+)}  $txt {\1\2'\3'}]
                        }
              {rfc}     { set head "List of RFC related to SSL, TLS" }
              {glossar} { set head "Glossar" }
              {text}    { set head "Texts used in various messages" }
              {ourstr}  { set head "Regular expressions to match our own strings" }
              {range}   { set head "List of cipherranges" }
              {compliance} { set head "INFO: Available commands for compliance checks" }
              {todo}    { set head "Known problems and bugs"              }
            }
            append info "\n\nINFO $head\n$txt"   ;# initial TAB for $txt important
        }
    }
    _dbx 4 " 2. merge HELP and additional help texts"
    set help [regsub {(\n\nATTRIBUTION)} $help "$info\n\nATTRIBUTION"];
    set help [regsub -all {===.*?===} $help {}]    ;# remove informal messages

    #dbx " 3. building TOC from section head lines here is difficult, done in create_help()"

    return $help
}; # osaft_help

proc osaft_reset  {}        {
    #? reset all options in cfg()
    _dbx 2 "{}"
    global cfg
    guistatus_set "reset"
    foreach {idx val} [array get cfg] {
        if {[regexp {^[^-]} $idx]}     { continue };# want options only
        if {[string trim $val] eq "0"} { continue };# already ok
        if {[string trim $val] eq "1"} {
            set cfg($idx]) 0
        } else {
            set cfg($idx]) ""
        }
    }
    return
}; # osaft_reset

proc osaft_init   {}        {
    #? set values from .o-saft.pl in cfg()
    _dbx 2 "{}"
    global cfg prg
    if {[regexp {\-docker$} $prg(SAFT)]} { return };# skip in docker mode
    foreach l [split $cfg(.CFG) "\r\n"] {
        # expected lines look like:
        #  --no-header
        #  --cfg_cmd=bsi=xxx yyy
        #
        if {[regexp "^\s*(#|$)" $l]} { continue }  ;# skip comments
        if {[regexp {=} $l]} {
            regexp $prg(rexOPT-cfg) $l dumm idx val
            # FIXME: there may be multiple  --cfg_cmd=KKK=VVV  settings, but
            #        there is only one variable in the GUI, so last one wins
            set idx [string trim $idx]
        } else {
            set idx [string trim $l]
            set val 1
        }
        _dbx 4 " cfg($idx) = »$val«"
        set cfg($idx) $val
    }
    return
}; # osaft_init

proc _get_table   {tbl}     {
    #? return all line from the text widget (table) $tbl, except the hidden ones
    # lines are formatted like result from O-Saft (roughly, not exactly)
    set txt ""
    set n   -1
    foreach l [$tbl get 0 end] {
        incr n
        if {[$tbl rowcget $n -hide]} { continue }
        set label [lindex $l 1]
        set value [lindex $l 2]
        set cmt   [lindex $l 3]
        append txt "$label:\t$value $cmt\n"
    }
    return $txt
}; # _get_table

proc osaft_save   {tbl type nr} {
    #? save selected output from text widget $tbl to file; $nr used if $type == TAB
    # $type denotes type of data (TAB = results() or CFG = cfg()); $nr denotes entry
    _dbx 2 "{$tbl, $type, $nr}"
    global cfg prg results
    if {$type eq "TTY"} {
        # FIXME: following type of TAB needs to be identified individually, not globally
        switch $cfg(layout) {
            text    { puts $results($nr) }
            table   { puts [_get_table $tbl] }
        }
        return     ;# ready
    }
    set title  [$cfg(objT) tab $nr -text];# get TAB's title
    set suffix [regsub -all {\s*\([0-9]*\)\s*} $title  {}] ;# remove (index)
    set suffix [regsub -all {[^a-zA-Z0-9_+-]}  $suffix {_}];# sanatize for filename
    if {$type eq "TAB"} {
        set name [tk_getSaveFile {*}$cfg(confirm) -title "$cfg(TITLE): [_get_tipp saveresult]" -initialfile "$prg(SAFT)--$suffix.log"]
        if {$name eq ""} { return }
        set fid  [open $name w]
        switch $cfg(layout) {
            text    { puts $fid $results($nr) }
            table   { puts $fid [_get_table $tbl] }
        }
    }
    if {$type eq "CFG"} {
        set name [tk_getSaveFile {*}$cfg(confirm) -title "$cfg(TITLE): [_get_tipp saveconfig]" -initialfile ".$prg(SAFT)--new"]
        if {$name eq ""} { return }
        set fid  [open $name w]
        foreach {idx val} [array get cfg] { # collect selected options
            if {[regexp {^[^-]} $idx]}     { continue } ;# want options only
            if {[string trim $val] eq "0"} { continue } ;#
            if {[string trim $val] eq "1"} {
                puts $fid "$idx"
            } else {
                if {$val ne ""} { puts $fid "$idx=$val" }
            }
        }
    }
    _dbx 4 " file = $name"
    close $fid
    guistatus_set "TAB »$title« saved to $name"
    return
}; # osaft_save

proc osaft_load   {cmd}     {
    #? load results from file and create a new TAB for it
    _dbx 2 "{$cmd}"
    global cfg results
    if {$cmd eq "Load"} {
        set name [tk_getOpenFile -title "$cfg(TITLE): [_get_tipp loadresult]"]
    } else {
        set name $cmd
    }
    if {$name eq ""} { return }
    guicursor_set watch
    incr cfg(EXEC)
    set fid [open $name r]
    set results($cfg(EXEC)) [read $fid]
    close $fid
    set txt [create_tab  $cfg(objT) $cfg(layout) $cmd $results($cfg(EXEC))]
    apply_filter $txt $cfg(layout) $cmd    ;# text placed in pane, now do some markup
    # TODO: filter may fail (return Tcl error) as data is not known to be table or text
    #puts $fid $results($nr)
    guistatus_set "loaded file: $name"
    guicursor_set {}
    return
}; # osaft_load

proc osaft_exec   {parent cmd}  {
    #? run $prg(SAFT) with given command; write result to global $osaft
    # $parent is a dummy here
    _dbx 2 "{$cmd}"
    global cfg hosts prg results
    guicursor_set watch
    guistatus_set "#{ $cmd"
    set do  {};     # must be set to avoid tcl error
    set opt {};     # ..
    set targets {}; # ..
    if {[regexp {\-docker$} $prg(SAFT)]} {
        # pass image ID to Docker;
        # note that this option must be before o-saft.pl commands or options
        lappend do "-id=$prg(docker-id)"
        lappend do "-tag=$prg(docker-tag)"
    }
    if {$cmd eq "Start"} {
        foreach {idx val} [array get cfg] { # collect selected commands
            if {[regexp {^[^+]} $idx]}     { continue }; # want commands only
            if {[string trim $val] ne "1"} { continue };
            lappend do $idx
        }
    } else {
        lappend do $cmd
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
    # check for some special docker commands; # TODO: quick&dirty
    if {$cmd eq "docker_status"} {
        # o-saft-docker status  has no other options
        set targets {}
        set opt     {}
        set do      "-id=$prg(docker-id)"
        lappend do  "-tag=$prg(docker-tag)"
        lappend do  "status"
    }
    if {[regexp {^win(32|64)} [tk windowingsystem]]} {
        set execcmd [list exec {*}$prg(PERL) $prg(SAFT) {*}$opt {*}$do {*}$targets]; # Tcl >= 8.5
        # Microsoft windows has no proper STDERR etc.
    } else {
        set execcmd [list exec 2>@stdout {*}$prg(PERL) $prg(SAFT) {*}$opt {*}$do {*}$targets]; # Tcl >= 8.5
        # on some systems (i.e. Mac OS X) buffering of STDOUT and STDERR is not
        # synchronized, hence we redirect STDERR to STDOUT, which is OK herein,
        # because no other process can fetch STDERR or STDOUT.
        # probaly we also need:  chan configure stdout -buffering none
    }
    # sanatize $execcmd for printing in status line and results TAB
    # Tcl uses {} to quote strings, which need to be '' for a shell
    # finally we use $execcmd for execution and $exectxt for print
    set exectxt $execcmd
    set exectxt [regsub {^\s*exec\s*.*?stdout\s*} $exectxt {}] ;# remove exec ..
    set exectxt [regsub -all {[\}\{]} $exectxt {'}]            ;# replace {}
    guistatus_set "$exectxt"
    incr cfg(EXEC)
    set result  ""
    set status  0
    putv          " $execcmd "
    if {[catch { {*}$execcmd } result errors]} {
        # exited abnormaly, get status and sanatize result
        # dict get $errors --errorcode   looks like:  CHILDSTATUS 9498 42
        # dict get $errors --errorinfo   returns same as we have in $results
        # because STDERR was redirected to STDOUT
        # Tcl's exec added  "child process exited abnormally"  to the result
        _dbx 4 " error  = [dict get $errors -errorcode]"
        set status [lindex [dict get $errors -errorcode] 2]
        set result [regsub {child process exited abnormally$} $result ""]
        # more pedantic check:
        #if {[lindex [dict get $errors -errorcode] 0] eq "CHILDSTATUS"} {
        #    # do something ...
        #}
    #else: nothing to do, everything in $result
    }
    set results($cfg(EXEC)) "\n$exectxt\n\n$result\n"      ;# store result for later use
    set _layout $cfg(layout)
    if {[regexp {[+]version$} $cmd]} { set _layout "text" };# no table data (only 2 columns)
    if { "docker_status"  eq  $cmd}  { set _layout "text" };# don't need table here
    set txt [create_tab  $cfg(objT) $_layout $cmd $results($cfg(EXEC))]
    apply_filter $txt $_layout $cmd    ;# text placed in pane, now do some markup
    destroy $cfg(winF)                 ;# workaround, see FIXME in create_filtertab
    guistatus_set "#} $do done (status=$status)."  ;# status not yet used ...
    guicursor_set {}
    return
}; # osaft_exec

#_____________________________________________________________________________
#_____________________________________________________________________ main __|

set targets "";                 # will later be copied to hosts()
set doit    0;
foreach arg $argv {
    switch -glob $arg {
        --h         -
        --help      { puts [osaft_about "HELP"]; exit; }
        --help=opts { osaft_write_opts;   exit; }
        +VERSION    { puts $cfg(VERSION); exit; }
        --version   { puts $cfg(mySID);   exit; }
        --rc        { osaft_write_rc;     exit; }
        +quit       { set   cfg(quit)   1;  }
        -docker     -
        --docker    { set   prg(SAFT)   "o-saft-docker"; }
        --dbx       -
        --d         { set   cfg(DEBUG)  1;  }
        --d=*       { set   cfg(DEBUG)  [regsub {^--d=} $arg {}]; }
        --trace     { set   cfg(TRACE)  1;  }
        --v         { set   cfg(VERB)   1;  }
        --gui       { }
        --image     -
        --img       { set   cfg(bstyle) "image";}
        --text      { set   cfg(bstyle) "text"; }
        --tip       { set   cfg(TIP)    1;  }
         -id=*      { set   prg(docker-id)  [regsub {^-id=}    $arg {}]; }
        --id=*      { set   prg(docker-id)  [regsub {^--id=}   $arg {}]; }
         -tag=*     { set   prg(docker-tag) [regsub {^-tag=}   $arg {}]; }
        --tag=*     { set   prg(docker-tag) [regsub {^--tag=}  $arg {}]; }
        --load=*    { lappend cfg(files)    [regsub {^--load=} $arg {}]; }
        --post=*    { set   prg(post) $arg; }

        options__for_debugging__only  { set dumm "" }
        --test-o-saft -
        --test-osaft  -
        --testosaft   { set cfg(DEBUG) 99;  }

        --*         { set cfg($arg) 1;      }
        +*          { set cfg($arg) 1; set doit 1;     }
        *           { lappend targets $arg; }
        default     { pwarn "unknown parameter »$arg«; ignored" }
    }
}
if {$cfg(DEBUG)> 0} { set cfg(VERB) 1; }
if {$cfg(TRACE)> 0} { trace_commands;  }
if {$cfg(VERB) > 0} { lappend prg(Ocmd) {+quit} {+version}; }
if {[regexp {\-docker$} $prg(SAFT)]} { lappend prg(Ocmd) {docker_status}; }

#| read $cfg(RC) if any
#  if the file does not exist, the error is silently catched and ignored
set rcfile [file join $env(HOME) $cfg(RC)]
if {[file isfile $rcfile]} { catch { source $rcfile } error_txt }
set rcfile [file join {./}       $cfg(RC)]
putv " source $rcfile"
if {[file isfile $rcfile]} { catch { source $rcfile } error_txt }
update_cfg;                     # update configuration as needed

#| read $cfg(IMG)               # must be read before any widget is created
read_images $cfg(bstyle);       # more precisely: before first use of guitheme_set

# FIXME: prg(docker-id) is missing here;  hence cfg(HELP), cfg(OPTS), cfg(CMDS)
#        will be empty if O-Saft's default Docker image is not (found) running
#        workaround: use environment variables, see o-saft-docker
set cfg(HELP)   [osaft_help]   ;# calls also:  $prg(SAFT) +help
putv                      " exec {*}$prg(PERL) $prg(SAFT) [docker_args] --help=opt"
set cfg(OPTS)   ""; catch { exec {*}$prg(PERL) $prg(SAFT) [docker_args] --help=opt }      cfg(OPTS)
putv                      " exec {*}$prg(PERL) $prg(SAFT) [docker_args] --help=commands"
set cfg(CMDS)   ""; catch { exec {*}$prg(PERL) $prg(SAFT) [docker_args] --help=commands } cfg(CMDS)

if {5 > [llength [split $cfg(CMDS) "\n"]]} {
    # failed, so we have no commands, no options and no help text
    # checking cfg(CMDS) is sufficient, as without commands nothing can be done
    tk_messageBox -icon error -title "**ERROR: $prg(SAFT) failed" \
        -message "$prg(SAFT) did not return list of commands
----
$cfg(CMDS)
----
"
    exit 2
}

#| special debug output
if {99==$cfg(DEBUG)} { puts "$cfg(HELP)"; exit; }

gui_init

#| create toplevel window
wm title        . $cfg(TITLE)
wm iconname     . [string tolower $cfg(TITLE)]
wm geometry     . $myX(geoS)

bind . <Control-v> {clipboard get}
bind . <Control-c> {clipboard clear ; clipboard append [selection get]}

#| create main window, see  #| main {  ..  #| main }  above
create_main $targets

#| load files, if any
foreach f $cfg(files) {
    if {![file exists $f]} { continue }
    osaft_load $f
}

#| GUI ready, initilize tracing if required
if {$cfg(TRACE) > 0} { trace_buttons }

#| some verbose output
putv " hosts= $hosts(0)"
set vm "";      # check if inside docker
if {[info exist env(osaft_vm_build)]==1}    { set vm "($env(osaft_vm_build))" }
if {[regexp {\-docker$} $prg(SAFT)]}        { set vm "(using $prg(SAFT))" }
guistatus_set "$argv0 $vm $argv"
    # full path and all passed arguments; useful if started from .desktop file

# must be at end when window was created, otherwise wm data is missing or mis-leading
if {$cfg(VERB)==1 || $cfg(DEBUG)==1} {
    if {[info commands console] eq "console"} { console show }; # windows hack
    # cfg(RCSID) set in RC-file
    set rc  "not found"; if {[info exists cfg(RCSID)]==1} { set rc  "found" };
    set ini "not found"; if {$cfg(.CFG) ne ""}            { set ini "found" };
    set tip "not used";  if {$cfg(TIP)  == 0 }            { set tip "used" };
    set geo "";          if {[info exists geometry]==1}   { set geo "$geometry" }
    set wmf "(shown with --d only"
    set max "(shown with --d only"
    if {$cfg(DEBUG)==1} {
        # use with --d only to avoid noisy output with "make test"
        set max [wm maxsize .]
        set wmf [wm frame   .] ;# returns a pointer
        if {[info exists env(OSAFT_MAKE)] == 1} {
            set wmf {<<value not printed (OSAFT_MAKE exists)>>}
            # TODO: string should be STR_MAKEVAL from osaft.pm
        }
    }
   #.CFG:      $cfg(.CFG)   # don't print, too much data

    puts [regsub -all -lineanchor {^} "
PRG $argv0 -- $cfg(ICH)
 |  RC        = $cfg(RC)\t$rc
 |  O-Saft    = $prg(SAFT)
 |  INIT      = $prg(INIT)\t$ini
 |  post      = $prg(post)
ARG argv      = $argv
 |  targets   = $targets
 |  files     = $cfg(files)
CFG TITLE     = $cfg(TITLE)
 |  debug     = $cfg(DEBUG)
 |  trace     = $cfg(TRACE)
 |  tooltip   = tooltip package\t$tip
 |  bstyle    = $cfg(bstyle)
 |  layout    = $cfg(layout)
 |  BROWSER   = $prg(BROWSER)
 |  PERL      = $prg(PERL)
 |  SAFT      = $prg(SAFT)
TCL version   = $::tcl_patchLevel
 |  library   = $::tcl_library
 |  platform  = $::tcl_platform(platform)
 |  os        = $::tcl_platform(os)
 |  osVersion = $::tcl_platform(osVersion)
 |  byteOrder = $::tcl_platform(byteOrder)
 |  wordSize  = $::tcl_platform(wordSize)
 |  rcFileName= $::tcl_rcFileName
Tk  version   = $::tk_patchLevel
 |  library   = $::tk_library
 |  strictMotif= $::tk_strictMotif
WM  frame     = $wmf
 |  maxsize   = $max
 |  geometry  = [wm geometry   .]
 |  focusmodel= [wm focusmodel .]
 |  system    = [tk windowingsystem]
 |  clipboard = $myX(buffer)
 |  geometry  = $geo
TAB tabs      = [$cfg(objT) tabs]
 |  count     = $cfg(EXEC)
 |
_/" "#\[$cfg(ICH)\]:"] ;# same prefix as in putv
    #          [tk windowingsystem] # we believe this a window manager property

}

#| start main (event loop)
if {1 == $doit}      { osaft_exec . "Start"; } ;# call o-saft.pl if commands are given

if {1 == $cfg(quit)} { putv " exit"; exit }

