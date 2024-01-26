#!/bin/sh
#| restarts using wish \
exec wish "$0" ${1+"$@"}

#!#############################################################################
#!#             Copyright (c) 2024, Achim Hoffmann
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
#?      It can be used to read saved results from other calls of o-saft.pl.
#?
#?      Any argument starting with  +  are considered a command for  o-saft.pl
#?      and  o-saft.pl  will be started with all other  options,  commands and
#?      targets and show the results in the GUI.
#?
#?   Result TAB
#?      The results of  o-saft.pl  are shown in a new TAB. The format (layout)
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
#?      All functionality is documented with balloon help on each checkbutton,
#?      input field, button or table header line.
#?
#?   Examples for Filter
#?      Match complete line containing Certificate:
#?         r=1 e=0 #=0 Regex=Certificate
#?      Match word Target:
#?         r=0 e=1 #=6 Regex=Target
#?      Match label text and emphase:
#?         r=1 e=0 #=1 Regex=^[A-Za-z][^:]*\s* Font=osaftHead
#?
#?   Configuration
#?      Some parts of the GUI, for example widget fonts or widget label texts,
#?      can be customised in  .o-saft.tcl , which  will be searched for in the
#?      user's  HOME directory  and in the local directory.
#?      Please see  .o-saft.tcl  itself for details. A sample  .o-saft.tcl  is
#?      available in the usr/ directory or can be created with  --rc .
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
#?        smart - convert pattern to RegEx: each character may be optional
#?        fuzzy - convert pattern to RegEx: each position may be optional
#?      Example:
#?        exact:  (adh|dha) - search for literal text  (adh|dha)
#?        regex:  (adh|dha) - search for word  adh  or  word  dha
#?        regex:  her.*list - search for text  her  followed by  list
#?        regex:  (and      - fails, because of syntax error
#?        smart:  and       - search for  and  or  a?nd  or  an?d  or  and?
#?        fuzzy:  and       - search for  and  or  .?nd  or  a.?d  or  an.?
#?
#?      Note: RegEx are applied to lines only, pattern cannot span more than a
#?            single line.
#?      The pattern must have at least 4 characters, except for mode "exact".
#?
#?      The GUI contains various [?] buttons. Clicking such a button will show
#?      the corresponding section in the help window (context sensitive).
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
#?      This behaviour is disabled with the  --test-tcl  option.
#?
#?   Key Bindings
#?      Following key bindings are defined:
#?        <ButtonPress>                 start browser with selected link
#?        <Control-ButtonPress-1>       copy text to clipboard (see above)
#?        <Shift-Control-ButtonPress-1> copy text to clipboard (see above)
#?        <Control-v>      copy text from clipboard
#?        <Control-c>      copy selected text to clipboard
#?        q         (quit) terminate Window or program (not in main window)
# ?
# ?     Key bindings currently (2023) not used  because they can't be disabled
# ?     in  entry or text  widgets then:
# ?       !         show window with About text
# ?       ?         show window with Help text
# ?       c         show window ciphers
# ?       d         show window tool settings (with --debug only)
# ?       h         show window with Help text
# ?       q         (quit) terminate Window or program
#?
#? OPTIONS
#?   Options for information and help:
#?      --h         print this text
#?      --help=opts print options (for compatibility with o-saft.pl)
#?      --version   print version number
#?      +VERSION    print version number (for compatibility with o-saft.pl)
#?
#?   Options for configuration and startup behaviour:
#?      --rc        print template for .o-saft.tcl
#?      --no-docs   use configuration texts returned from o-saft.pl instead of
#?                  reading prepared static files
#?      --gen-docs  generate static files for configuration texts
#?      --pod       use podviewer to show help text
#?      --tkpod     use tkpod to show help text
#?      --stdin     read data from STDIN and show in result TAB
#?      --load=FILE read data from FILE and show in result TAB
#?
#?   Options for use with docker:
#?      --docker    use o-saft-docker instead of o-saft.pl
#?      --docker-id=ID
#?                  use Docker image ID (registry:tag); default: owasp/o-saft
#?      --docker-tag=ID      use Docker image ID with tag; default: (empty)
#?
#?   Options for GUI behaviour:
#?      --gui       dummy for compatibility with other tools
#?      --gui-tip   use own tooltip
#?      --gui-button=text    use simple texts as labels for buttons
#?      --gui-button=image   use images for buttons (see o-saft-img.tcl)
#?              (not recommended on Mac OS X, because Aqua has nice buttons)
#?      --gui-layout=classic tool layout for view on desktop
#?      --gui-layout=tablet  tool layout for tablet, smartphone; default
#?      --gui-result=text    print result of o-saft.pl as simple plain text
#?      --gui-result=table   print result of o-saft.pl formated in a table
#?
#?   Options for debugging:
#?      --v     print verbose messages (startup and calling external tools)
#?      --d     print more verbose messages (for debugging)
#?      --d=D   print debug messages according level
#?              D=1     - print verbose messages (main)
#?              D=2     - print proc calls (those not triggerd by events)
#?              D=4     - print debugging in proc
#?              D=8     - print verbose debugging for "help" window
#?              values can be combined, like  --d=6  to print procs and data,
#?              all  --d=*  imply  --v
#?      --trace     use Tcl's trace to trace proc calls
#?
#?   Options for testing:
#?      +quit       exit without GUI (for compatibility with o-saft.pl)
#?      --test=FILE read FILE and print on STDOUT; used for testing only
#?      --test-docs just print used external  o-saft.pl.--help=*  files
#?      --test-tcl  just print debug information; similar to: --d +quit
#?      --test-osaft    just print text used for help window (help button)
#?
#?   Option aliases for compatibility with other programs or legacy:
#?      # Alias     Option
#?      #----------+--------------------
#?      --image     --gui-button=image
#?      --text      --gui-button=text
#?      --tip       --gui-tip
#?      --id=ID     --docker-id=ID
#?      --tag=TAG   --docker-tag=TAG
#?
#?   Options passed through to o-saft.pl:
#?      +*          any option starting with +
#?      --*         any other option starting with --
# TODO: --post=PRG  --post=  parameter passed to o-saft
#?
#? DOCKER
#?      This script can be used from within any Docker image. The host is then
#?      responsible for providing the proper protocols for the GUI (i.e. X11).
#?      In this case,  anything is executed inside the Docker image,  just the
#?      graphical output is passed to the host. This mode is started with:
#?          o-saft-docker --gui
#?      which does the necessary magic with Docker for protocol and DISPLAY.
#?
#?      When used with the  --docker  option, this script runs on the host and
#?      connects to an  O-Saft Docker image  to execute  o-saft.pl  there with
#?      all the selected commands and options.
#?      In this mode,  o-saft-docker  will be used instead of o-saft.pl, which
#?      must be available on the host.
#?      Note that  o-saft-docker  relies on O-Saft's Docker image osawp/o-saft
#?      which has its own (Docker) entrypoint.  This means that  o-saft-docker
#?      is responsible to provide the same functionality as  o-saft.pl  does.
#?      Adaptions, if necessary, should be done in  o-saft-docker.
#?
#?      Summary
#?          o-saft.tcl --docker     - run on host using o-saft.pl in Docker
#?          o-saft-docker --gui     - run in Docker with display to host
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
#?      GUI herein, in particular when texts are changed with this option.
#?
#?      Some  --legacy=*  options are not handled properly.  In particular the
#?      result looks corrupted in table view when the option  --legacy=compact
#?      or  --legacy=full  is used; , use the text view for that.
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
#?      To pipe data in on STDIN, the option  --stdin  must be used, otherwise
#?      it will not be read.
#?
#?      STDIN  and  _LOAD  as filenames can not be used to load data.
#?
#?      Not really a problem, but worth to mention:
#?      It's not possible to map cipher suites to the proper  SSL/TLS protocol
#?      in the results TAB in table view. Therefore the cipher suite names are
#?      prepended by the protocol.
#?      Due technical reasons, the protocol and the cipher suite name  will be
#?      separated by the non-breaking space character U+2007.
#?      Take care when processing saved results, [Save] and [STDOUT] button.
#?
#? ARGUMENTS
#?      All arguments,  except the options described above,  are treated  as a
#?      hostname to be checked.
#?
#? ADDITIONAL SYNOPSIS
#?      On some systems (i.e. Android) it could be difficult to pass arguments
#?      and/or options to this script.  To simulate passing options, following
#?      alias names are provided:
#?          o-saft--testtcl.tcl
#?          o-saft--test-docs.tcl
#?          o-saft--trace.tcl
#?          o-saft--d.tcl
#?          osaft--testtcl.tcl
#?          osaft--test-docs.tcl
#?          osaft--trace.tcl
#?          osaft--d.tcl
#?
#? SEE ALSO
#?      o-saft
#?      o-saft.pl
#?      o-saft-docker
#?
#. LAYOUT
#.      --gui-layout=tablet
#.           +---------------------------------------------------------------+
#.       (M) | ☰  Cmd  Opt  Config                                           |
#.           |---------------------------------------------------------------|
#.       (H) | Host:Port [________________________________________]  [+] [-] |
#.           |                                                               |
#.           | +----------++----------+                                      |
#.       (R) | | (n) +cmd || (m) +cmd |                                      |
#.           | +          +------------------------------------------------+ |
#.           | |                                                           | |
#.           | |                                                           | |
#.           | +-----------------------------------------------------------+ |
#.           |---------------------------------------------------------------|
#.           |---------------------------------------------------------------|
#.       (S) | |                                                           | |
#.           +---------------------------------------------------------------+
#.
#.      --gui-layout=classic
#.           +---------------------------------------------------------------+
#.       (H) | Host:Port [________________________________________]  [+] [-] |
#.           |                                                       [!] [?] |
#.       (C) | [Start] [+info] [+check] [+cipher] [+quick] [+vulns]   [Load] |
#.       (O) | [ ] --header  [ ] --enabled  [ ] --no-dns  [ ] -no-http  ...  |
#.           |---------------------------------------------------------------|
#.           | +----------++---------++--------++----------++----------+     |
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
#.       (M) - Frame containing menus for  all commands, commands, options
#.        ☰  - menubutton for  all commands and options
#.       Cmd - menubutton for  quick commands (most often used)
#.       Opt - menubutton for  quick options (most often used)
#.       Cfg - menubutton for  configuration settings
#.       (C) - Buttons for most commonly used commands
#.       (O) - CheckButtons for most commonly used options
#.       (R) - Frame containing panes for results
#.       (T) - Frame containing panes for commands, options, filter, results
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
#.      For the main workflow use the  --trace  option, for example:
#.          $0 --trace +quit
#.          $0 --trace --gui-layout=classic
#.
#. LIMITATIONS
#.      All help texts reference to the default hardcoded texts,  even if they
#.      are changed in  .o-saft.tcl .
#.
#. HACKER's INFO
#.   TODO (8/2016):
#.      - need to check if ugly hacks for Aqua (Mac OS X 10.6  with  Tk 8.5.7)
#.        are still necessary on modern Macs, in particular:
#.        * tk_getSaveFile -confirmoverwrite
#.        * package require Img
#.
#.      This is no academically perfect code, but quick&dirty scripted:
#.       - makes use of global variables instead of passing parameters etc..
#.       - mixes layout and functions and application logic
#.       - some widget names are hardcoded
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
#.      ATTRIBUTION  section. Hence  ATTRIBUTION  must exist as section header
#.      in output of "o-saft.pl +help".
#.
#.      The tool will only work if o-saft.pl is available and executes without
#.      errors. All commands and options of  o-saft.pl  will be available from
#.      herein, except:
#.          - all  "--help*"  options (as they make no sense here)
#.          - "+cgi"  and  "+exec"  command (they are for internal use only)
#.
#.   Some Naming Conventions
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
#.          exe()       - global variable containing commands and options for
#.                        o-saft.pl from command-line
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
#.                        comment; the  ;  is usually right before the  #
#.
#.   Coding (general)
#.      Sequence of function definitions done to avoid forward declarations.
#.      See  Debugging Options  below also.
#.
#.   Coding (GUI)
#.      Images (i.e. for buttons) are defined in o-saft-img.tcl, which must be
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
#.      Starting 11/2021 the default tool layout was changed from "classic" to
#.      "tablet". This only affects building the GUI itself. The difference in
#.      building the GUI is mainly controlled by the variable cfg(gui-layout).
#.      This effects the procs: create_host() create_buttons() and gui_main().
#.
#.   STDIN
#.      Tcl's file handle (channel) for STDIN is named stdin, which is open by
#.      default. Data piped to  $0  can be read from this file handle.
#.      But it is difficult to detect if data is available from stdin, if not,
#.      Tcl's  get()  function simply hangs. To avoid this, the option --stdin
#.      must be used if data should be read from STDIN, example:
#.          cat some-file | $0 --stdin
#.          o-saft.pl +check localhost   | $0 --stdin
#.      Reading from STDIN can simply be tested like
#.          echo "label: no any comment" | $0 --stdin
#.
#.      Note that STDIN is used as filename to indicate that Tcl's stdin  file
#.      handle should be used (which needs to be treated special).
#.
#.   Tracing (GUI)
#.      Tcl's  trace  functionality is used to trace most procs defined herein
#.      and all created buttons. See  trace_commands() and trace_buttons() for
#.      details. Tracing does not yet work for buttons created in sub-windows.
#.      Tracing is invoked with the  --trace  option.
#.
#.   Tracing (program flow)
#.      --d=X         - see description above
#.
#.   Tracing and Debugging
#.      All output for  --trace  and/or  --dbx  is printed on STDERR.
#.      Trace messages are prefixed with:   #[$0]:
#.      Debug messages are prefixed with:   #dbx# [$0]:
#.
#.      --test=FILE
#.      --test=FILE --gui-result=text
#.      --test=FILE --gui-result=table
#.          loads FILE into the GUI's tablelist widget and then calls the save
#.          function, which prints the content of tablelist on STDOUT.
#.          This is used in Makefile* for testing functionality, does not make
#.          any sense otherwise.
#.          The  --gui-result=*  option enforces to display and store the file
#.          content in Tk's tablelist or text widget. The displayed output may
#.          be slightly different, as the tablelist doesn't always contain all
#.          data of the file.
#.
#.   Tracing and Debugging with Alias Names
#.      If arguments (options) can not be passed to the script, alias names of
#.      the script can be used to simulate passed options:
#.      # alias name            # behaves as called like
#.      #-----------------------#-------------------------------
#.      o-saft--testtcl.tcl     $0 --test-tcl
#.      o-saft--d.tcl           $0 --d
#.      o-saft--trace.tcl       $0 --trace
#.
#.   Notes About Tcl/Tk
#.      We try to avoid platform-specific code. The only exceptions since 2015
#.      are the perl executable and the start method of the external browser.
#.      Another exception (8/2016) is "package require Img" which is necessary
#.      on some Mac OS X.
#.      All external programs are started using Tcl's  {*}  syntax.
#.
#.      If there is any text visible, we want to copy&paste it. Therefore most
#.      texts are placed in Tk's text widget instead of a label widget, 'cause
#.      text widgets allow selecting their content by default, while labels do
#.      not. These text widgets are set to state "read-only"  instaed of Tcl's
#.      disabled state, see gui_set_readonly() for details.
#.
#? VERSION
#?      @(#) 3.4 Winter Edition 2024
#?
#? AUTHOR
#?      04. April 2015 Achim Hoffmann
#?
#?      Project Home: https://owasp.org/www-project-o-saft/
#?      Help Online:  https://www.owasp.org/index.php/O-Saft/Documentation
#?                    https://wiki.owasp.org/index.php/O-Saft/Documentation
#?      Repository:   https://github.com/OWASP/O-Saft
#?
# -----------------------------------------------------------------------------

set cfg(testtcl) 0
#package require Tcl     8.5    ;# for documentation only
#package require Tk      8.5    ;# modern Tcl/Tk doesn't need it anymore
if {![regexp -- {--test-?tcl} $argv]} {
    # keep some systems quiet
    package require Tk
    set cfg(testtcl) 1
}

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

if {0<$cfg(testtcl)} {
    # do not bind in debug-only mode to avoid errors, see "Key Bindings"
    foreach klasse [list  Button  Combobox  Entry  Label  Text Message Spinbox \
                         TButton TCombobox TEntry TLabel TText Frame Menu \
                         LabelFrame  PanedWindow Scale Scrollbar \
                         Checkbutton Menubutton  Radiobutton Dialog] {
        bind $klasse  <Control-ButtonPress-1>       { copy2clipboard %W 0 }
        bind $klasse  <Shift-Control-ButtonPress-1> { copy2clipboard %W 1 }
    }
}

proc copy2clipboard {w shift} {
    #? copy visible text of object to clipboard
    global cfg
    set klasse [winfo class $w]
    set txt {}
    if {1==$shift} { set txt "$w $klasse: " }
    # TODO: Menu, Spinbox not complete; some classes are missing
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
       Menubutton   -
       Checkbutton  -
       Radiobutton  { append txt [lindex [$w config -text] 4] }
       Entry        -
       TEntry       { append txt [string trim [$w get]] }
       Text         -
       TText        { append txt [string trim [$w get 1.0 end]] }
       default      { puts "** unknown class $klasse" }
    }
    if {1==$shift} {
        set cmd ""
        catch {lindex [$w config -command] 4} cmd  ;# show error or command
        append txt "\n -command $cmd"
    }
    putv "copy2clipboard($w, $shift): {\n $txt\n#}"
    clipboard clear
    clipboard append -type STRING -format STRING -- $txt
}; # copy2clipboard

#_____________________________________________________________________________
#____________________________________________________________ configuration __|

# this section mainly contains variable initialisations, it also defines some
# functions for easy acces to configurations
# following arrays contain the index DESC multiple times, which means that it
# will be overwritten; doesn't harm, because it's used for documentation only
# in the code herein

proc config_docker  {mode}  {
    #? initilise configuration for use with Docker image
    #  may be called with $mode=opt for --docker option or with $mode=prg to
    #  check if program name matches *-docker
    #  must be early definition, because called right after program start
    global cfg prg env argv0
    switch $mode {
       prg { if {[regexp {\-docker$} $argv0]} { set mode 1 } }
       opt { set mode 1 }
    }
    if {1==$mode} {
        set cfg(docker)  1
        set prg(SAFT)    "o-saft-docker"
    }
    # independent of mode, can always be set
    if {1==[info exists env(o_saft_docker_tag)] } { set prg(docker-tag) $env(o_saft_docker_tag)  }
    if {1==[info exists env(o_saft_docker_name)]} { set prg(docker-id)  $env(o_saft_docker_name) }
    return
}; # config_docker

if {![info exists argv0]} { set argv0 "o-saft.tcl" }   ;# if it is a tclet

set cfg(SID)    "@(#) o-saft.tcl 3.4 24/01/26 16:50:07"
set cfg(mySID)  "$cfg(SID) Winter Edition 2024"
                 # contribution to SCCS's "what" to avoid additional characters
set cfg(VERSION) {3.4}
set cfg(TITLE)  {O-Saft}
set cfg(RC)     {.o-saft.tcl}
set cfg(RCmin)  1.13                   ;# expected minimal version of cfg(RC)
set cfg(ICH)    [file tail $argv0]
set cfg(DIR)    [file dirname $argv0]  ;# directory of cfg(ICH)
set cfg(ME)     [info script]          ;# set very early, may be missing later
set cfg(IMG)    {lib/o-saft-img.tcl}   ;# where to find image data
                                        # O-Saft means built-in
set cfg(O-Saft) {o-saft.pl}            ;# common name of O-Saft executable
                                        # constant also used for filenames
set cfg(POD)    {o-saft.pod}           ;# complete help text in POD format
set cfg(HELP)   ""                     ;# O-Saft's complete help text
set cfg(files)  {}                     ;# files to be loaded at startup --load
set cfg(.CFG)   {}                     ;# contains data from prg(INIT)
                                       ;# set below and processed in osaft_init
set cfg(quit)   0                      ;# quit without GUI
set cfg(stdout) 0                      ;# 1: call osaft_save TTY
set cfg(docker) 0                      ;# 1: for --docker option or o-saft-docker
#et cfg(HELP-key) ""                   ;# contains linenumber of result table
set cfg(docs-dir)   $cfg(DIR)/doc      ;# directory where to find documentation
                                        # may be redifined in RC-file

#-----------------------------------------------------------------------------{
#   Definitions outside RC-ANF - RC-END scope, because they're not intended to
#   be changed in .o-saft.tcl .

#et exe()  ... # will contain commands and options from command-line

#   define some RegEx to match output from o-saft.pl or data in .o-saft.pl
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

#set _me [regsub -all {^[./]*} $prg(SAFT) {}] ;# remove ./ but prg(SAFT) later
    # causes problems in regsub on Mac OS X if $prg(SAFT) starts with ./
set prg(rexCOMMANDS) "\(o-saft\(.pl|.tcl|-docker\)?|checkAllCiphers.pl|\(/usr/local/\)?openssl|docker|mkdir|ldd|ln|perlapp|perl2exe|pp\)"
    # most common tools used in help text...
set prg(POST)   {}             ;# --post=  parameter, if passed on command-line
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
set prg(Ocmd)   {{+check} {+cipher} {+info} {+quick} {+vulns} {+protocols} }
    # List of quick access commands, for which a button will be created in the
    # GUI. This must be commands of o-saft.pl, which start with  +  character.
    # +quit  and  +version  will be added for  --v  or  --d  only.
set prg(Oopt)   {{--header} {--enabled} {--no-dns} {--no-http} {--no-sni} {--no-sslv2} {--no-sslv3} }
    # List of quick access options,  a checkbox will be created in the GUI.
    # This must be options of o-saft.pl, which start with  --  character.

set myX(DESC)   {-- CONFIGURATION window manager geometry --------------------}
#   set minimal window sizes to be usable in a 1024x768 screen
#   windows will be larger if the screen supports it (we rely on "wm maxsize")
set myX(geoo)   "660x720"      ;# geometry of Help window

set myX(geoO) "$myX(geoo)-0+0" ;# geometry and position of Help      window
set myX(geo-)   "400x80"       ;# geometry and position of no match  window
set myX(geoS)   "700x720"      ;# geometry and position of O-Saft    window
set myX(geoA)   "660x610"      ;# geometry and position of About     window
set myX(geoC)   ""             ;# geometry and position of Config    window (computed dynamically)
set myX(geoD)   "700x700"      ;# geometry and position of Cipher    window
set myX(geoF)   "700x750"      ;# geometry and position of Filter    window
set myX(geoT)   ""             ;# geometry and position of Tool Cfg  window (computed dynamically)
set myX(minx)   700            ;# O-Saft  window min. width
set myX(miny)   850            ;# O-Saft  window min. height
set myX(lenl)   15             ;# fixed width of labels in Options window
set myX(rpad)   15             ;# right padding in the lower right corner
set myX(padx)   5              ;# padding to right border
set myX(maxS)   3              ;# height of status line

set cfg(DESC)   {-- CONFIGURATION GUI style and layout -----------------------}
set cfg(gui-button) {image}    ;# button style:  image  or  text
                                # used with --gui-layout=classic only
set cfg(gui-layout) {tablet}   ;# tablet:  tool layout for tablet, smartphone
                                # classic: tool layout for view on desktop
set cfg(gui-result) {table}    ;# layout o-saft.pl's results:  text  or  table
                                # see also comment in gui_init()
set cfg(tfont)  {flat9x6}      ;# font used in tablelist::tablelist
set cfg(max53)  4050           ;# max. size of text to be stored in table columns
#   Some combinations of Tcl/Tk and X-Servers are limited in the size of text,
#   which can be stored in Tk's table columns. When such a widget is rendered,
#   the script crashes with following error message:
#       X Error of failed request:  BadAlloc (insufficient resources for operation)
#         Major opcode of failed request:  53 (X_CreatePixmap)
#         Serial number of failed request:  2223
#         Current serial number in output stream:  2255
#   To avoid the crash, large texts (greater than this value) can be stripped.
#   The default value of ~4000 is based on experience.

set cfg(docs-src)   {file}     ;# file:    read configuration of commands and
                                #          options from static files in ./doc/
                                # dynamic: read configuration using o-saft.pl
set cfg(nbsp)   \u2007         ;# character used for non-breaking spaces

set cfg(DESC)   {-- CONFIGURATION misc settings ------------------------------}
set cfg(no-match)   {_NO_}     ;# text pattern used to avoid matching some text

# RC-END }
set cfg(docs-help)      {--help=alias --help=checks --help=data --help=glossar --help=regex --help=rfc --help}
                                # file extensions for files from ./doc/ used in osaft_read_data() and osaft_help()
                                # missing: --help=text --help=ourstr --help=compliance
                                # missing because too much data: --help=range
set cfg(docs-help-all)  "--help=commands --help=opts $cfg(docs-help) --help=ciphers-text"
                                # this list should be same as $cfg{'files'},
                                # see also man_docs_write() in in o-saft.pl
set cfg(docs-files) {}         ;# contains the read files from ./doc/
set cfg(guiwidgets) {}         ;# contains the widgets of the GUI
set cfg(guimenus)   {}         ;# contains the widgets of the GUI's menus
                                # debugging only for --gui-layout=tablet

config_docker prg              ;# may initialise some docker-specific settings

catch {
    set fid [open $prg(INIT) r] ;# read .o-saft.pl
    set cfg(.CFG) [read $fid]
    close $fid
}

#| configure GUI

set cfg(gui-tip)    [catch { package require tooltip} tip_msg];  # 0 on success, 1 otherwise!

set IMG(help) ::tk::icons::question
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

set my_bg       #d9d9d9        ;# default background color (lightgray)
                                # this colour is used for buttons too
                                # default background of Tk widget (if available)
catch { set my_bg "[lindex [.i config -bg] 4]" }

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
    # Note:   should be used after calling gui_init

    #----------+---------------+-------+-------+-------------------------------
    # object    button text colour   image      help text (aka tooltip)
    # name      -text       -bg     -image      guitip_set()
    #----------+-----------+-------+-----------+-------------------------------
array set cfg_buttons "
    about       {{!}        $my_bg  {!}         {About $cfg(ICH) $cfg(VERSION)}}
    help        {{?}        $my_bg  help        {Open window with complete help}}
    help_me     {{?}        $my_bg  {?}         {Open window with help for these settings}}
    closeme     {{Quit}     orange  quit        {Close program}}
    closewin    {{Close}    orange  close       {Close window}}
    closetab   {{Close Tab} orange  closetab    {Close this TAB}}
    loadresult    {{Load}   lightgreen load     {Load results from file}}
    saveresult    {{Save}   lightgreen save     {Save results to file}}
    saveconfig    {{Save}   lightgreen save     {Save configuration to file  }}
    ttyresult     {{STDOUT} lightgreen stdout   {Print results on systems STDOUT}}
    reset       {{Reset}    $my_bg  reset       {Reset configuration to defaults}}
    filter      {{Filter}   $my_bg  filter      {Show configuration for filtering results}}
    tkcolor   {{Color Chooser}  $my_bg tkcolor  {Open window to choose a color}}
    tkfont    {{Font Chooser}   $my_bg tkfont   {Open window to choose a font}}
    host_add    {{+}        $my_bg  {+}         {Add new line for a host}}
    host_del    {{-}        $my_bg  {-}         {Remove this line for a host }}
    help_home   {{^}        $my_bg  help_home   {Go to top of page (start next search from there)}}
    help_prev   {{<}        $my_bg  help_prev   {Search baskward for text}}
    help_next   {{>}        $my_bg  help_next   {Search forward for text}}
    help_help   {{?}        $my_bg  {?}         {Show help about search functionality}}
    helpreset   {{Reset}    $my_bg  reset       {Reset/clear list of search texts}}
    helpsearch  {{??}       $my_bg  helpsearch  {Text to be searched}}
    cmdstart    {{Start}    yellow  cmdstart    {Execute $prg(SAFT) with commands selected in 'Commands' tab}}
    cmdcheck    {{+check}   #ffd800 +check      {Execute $prg(SAFT) +check   }}
    cmdcipher   {{+cipher}  #ffd000 +cipher     {Execute $prg(SAFT) +cipher  }}
    cmdinfo     {{+info}    #ffc800 +info       {Execute $prg(SAFT) +info    }}
    cmdquit     {{+quit}    #ffc800 +quit       {Execute $prg(SAFT) +quit (debugging only)}}
    cmdquick    {{+quick}   #ffc000 +quick      {Execute $prg(SAFT) +quick   }}
    cmdprotocols   {{+protocols} #ffb800 +protocols {Execute $prg(SAFT) +protocols }}
    cmdvulns    {{+vulns}   #ffb000 +vulns      {Execute $prg(SAFT) +vulns   }}
    cmdversion  {{+version} #fffa00 +version    {Execute $prg(SAFT) +version }}
    docker_status  {{docker status} #00faff docker_status {Execute $prg(SAFT) status   }}
    img_txt     {{image/text} $my_bg {img_txt}  {toggle buttons: text or image}}
    DESC_menu   {-- for following rows, colour is the forground colour of the objekt --}
    menu_menu   {{☰}        orange         {}   {Main menu}}
    menu_cmd    {{Cmd}      white          {}   {Quick commands menu}}
    menu_opt    {{Opt}      white          {}   {Quick options menu}}
    menu_cfg    {{Config}   white          {}   {GUI configurations menu}}
    menu_cmds   {{ + All Commands}  {}     {}   {Commands submenu}}
    menu_opts   {{ -  All Options}  {}     {}   {Options submenu}}
    menu_load   {{    Load Results} {}     {}   {Load results from file}}
    menu_filt   {{  Config Filter} {}     {}   {Show configuration for filtering results}}
    menu_conf   {{  Config GUI}    {}     {}   {Show configuration for GUI settings}}
    menu_prog   {{  Config Tool}   {}     {}   {Show configuration for tool itself}}
    menu_mode   {{Change Layout}    {}     {}   {Toogle layout between classic and tablet}}
    menu_help   {{ ?  Help}         {}     help {Open window with complete help}}
    menu_list   {{  Cipher Suites} {}     {&}  {Open window with list of cipher suites}}
    menu_uber   {{❗  About}        {}     {!}  {About $cfg(ICH) $cfg(VERSION)}}
    menu_exit   {{⏻  Quit}          orange quit {Close program}}
    menu_rsave  {{Save}             {}     save {Save results to file}}
    menu_reset  {{Reset}            {}    reset {Reset configuration to defaults}}
";  #----------+-----------+-------+-----------+-------------------------------
    # name      -text           -bg     -image  guitip_set()
    #----------+-----------+-------+-----------+-------------------------------

    # Note: all buttons as described above,  can be configured also by the user
    # using  cfg(RC).  Configurable are:  text (-text), background colour (-bg)
    # and the tooltip.  Because configuring the above table is a bit cumbersome
    # for most users, we provide simple lists with key=value pairs. These lists
    # are: cfg_colors, cfg_texts and cfg_tipps. The settings here are defaults,
    # and may be redefined in cfg(RC) using  cfg_color, cfg_label and cfg_tipp.
    # These lists (arrays in Tcl terms) contain not just the button values, but
    # also values for other objects.  So the lists are initialised here for all
    # other values, and then the values from cfg_buttons are added.
    #
    # array in cfg(RC)  array herein   (see also update_cfg() )
    #     cfg_color     cfg_colors
    #     cfg_label     cfg_texts
    #     cfg_tipp      cfg_tipps

# functions to get above texts
proc _get_btn_txt {key} { global cfg_buttons; return [lindex $cfg_buttons($key) 0] }
proc _get_btn_bg  {key} { global cfg_buttons; return [lindex $cfg_buttons($key) 1] }
proc _get_btn_img {key} { global cfg_buttons; return [lindex $cfg_buttons($key) 2] }
proc _get_btn_tip {key} { global cfg_buttons; return [lindex $cfg_buttons($key) 3] }

array set cfg_colors "
    DESC        {-- CONFIGURATION colours used in GUI ------------------------}
    osaft       gold
    button      lightyellow
    code        lightgray
    link        blue
    status      wheat
"
# above texts are used with _get_color()

array set cfg_texts "
    DESC_search {-- CONFIGURATION texts used in GUI's Help window ------------}
    h_min4chars {Pattern should have more than 3 characters.}
    h_nomatch   {No matches found for}
    h_badregex  {Invalid RegEx pattern}
    DESC_texts  {-- CONFIGURATION texts used in GUI for buttons or labels ----}
    host        {Host\[:Port\]}
    hideline    {Hide complete line}
    c_toggle    {toggle visibility\nof various texts}
    DESC_table  {-- CONFIGURATION texts used for table headers ---------------}
    t_nr        Nr
    t_label     Label
    t_value     Value
    t_comment   Comment
    t_key       Key
    t_moder     r
    t_modee     e
    t_chars     {#}
    t_regex     RegEx
    t_fg        Foreground
    t_bg        Background
    t_font      Font
    t_u         u
    DESC_other  {-- CONFIGURATION texts used at various places ---------------}
    cfg_progs   {Used programs:}
    cfg_regex   {Used RegEx:}
    cfg_docker  {Docker setting:}
    gui_layout  {Layout format of results:}
    gui_button  {Style of buttons:}
    win_about   {About}
    win_cipher  {Cipher Suites}
    win_colour  {Colour}
    win_cmds    {Commands}
    win_opts    {Options}
    win_font    {Font}
    win_help    {Help}
    win_tool    {Tool Settings}
    win_config  {Config}
    win_filter  {Filter}
    win_search  {Search ...}
    win_search_results  {Search Results for:}
    no_browser  {no browser found}
    gen_docs    {
GUI may be incomplete

!!Hint:
use »$prg(SAFT) --help=gen-docs« to generate static files
    }
"
# above texts are used with _get_text()

array set cfg_tipps "
    DESC        {-- CONFIGURATION texts used for tool tips on buttons --------}
    settings    {Open window with more settings}
    open_browser {Open in browser:}
    layout      {Format used in result TAB}
    DESC_other  {-- CONFIGURATION texts used for tool tips on other objects --}
    choosen     {Choosen value for}
    hideline    {Hide complete line instead of pattern only}
    possible_values {possible values:}
    show_hide   {show/hide:}
    tabMENU     {Select commands and options in ☰ menu.}
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
    DESC_filter {-- CONFIGURATION texts used in Filter tab -------------------}
    t_key       {Unique key for regex}
    t_moder     {Modifier: use regex with regex pattern (-regexp)}
    t_modee     {Modifier: use regex with exact pattern (-exact)}
    t_chars     {Length to be matched (0: all text; -1: complete line to right end)}
    t_regex     {RegEx to match text}
    t_bg        {Background color used for matching text (empty: don't change)}
    t_fg        {Foreground color used for matching text (empty: don't change)}
    t_font      {Font used for matching text (empty: don't change)}
    t_u         {Underline matching text (0 or 1)}
    t_cmt       {Description of regex}
    DESC_opts   {-- CONFIGURATION texts used in GUI for option checkbuttons --}
    --header    {print header line}
    --enabled   {print only enabled ciphers}
    --no-dns    {do not make DNS lookups}
    --no-http   {do not make HTTP requests}
    --no-sni    {do not make connections in SNI mode}
    --no-sslv2  {do not check for SSLv2 ciphers}
    --no-sslv3  {do not check for SSLv3 ciphers}
    --no-tlsv13 {do not check for TLSv13 ciphers}
    docker-id   {Docker image ID (registry:tag) to be connected}
"; # cfg_tipps; # Note: text for tab* contain new lines.
# above texts are used with _get_tipp()

# now add default to cfg_* as described before
foreach key [array names cfg_buttons] {
    set cfg_colors($key) [_get_btn_bg  $key]
    set cfg_texts($key)  [_get_btn_txt $key]
    set cfg_tipps($key)  [_get_btn_tip $key]
    set cfg_images($key) [_get_btn_img $key]
}

# functions to get above texts
proc _get_color   {key} { global cfg_colors;  return $cfg_colors($key) }
    #? return color name for key from global cfg_colors variable
proc _get_text    {key} { global cfg_texts;   return $cfg_texts($key)  }
    #? return text string for key from global cfg_texts variable
proc _get_tipp    {key} { global cfg_tipps;   return $cfg_tipps($key)  }
    #? return text string for key from global cfg_tipps variable
proc _get_image   {key} { global cfg_images;  return $cfg_images($key) }
    #? return image for key from global cfg_images variablle
proc _get_padx    {key} { global myX;         return $myX($key)        }
    #? return padx value for key from global myX variable

proc _message     {icon title txt} {
    # print message, either with GUI or on STDERR
    if {""==[info commands tk_messageBox]} {
        puts stderr "# $icon: $title #\n$txt"
    } else {
        tk_messageBox -icon $icon -title "$title" -message "$txt"
    }
    return
};# _message

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
if {1==[info exists env(ANDROID_DATA)]} {
    # dirty hack to detect Android and adapt configuration
    set cfg(gui-button) "text" ;# text by default, because icons are too small
    set prg(PERL)       /data/data/com.termux/files/usr/bin/perl
        # FIXME: not working for all perl installations on Android
}
# NOTE:  as Tcl is picky about empty variables, we have to ensure later, that
# $prg(PERL) is evaluated propperly,  in particular when it is empty.  We use
# Tcl's  {*}  evaluation for that.

#| check if prg(SAFT) exists in PATH, +VERSION just prints the version number
#_dbx 3        " $prg(PERL) $prg(SAFT) +VERSION"; # _dbx() not yet defined
catch { exec {*}$prg(PERL) $prg(SAFT) +VERSION } usage
if {![regexp {^\d\d\.\d\d\.\d\d} $usage]} { # check other PATH
    set osaft "$cfg(DIR)/$prg(SAFT)"       ;# check in PATH of $argv0
    catch { exec {*}$prg(PERL) $osaft +VERSION }  usage
    if {![regexp {^\d\d\.\d\d\.\d\d} $usage]} {
        _message warning "**WARNING: (main)" \
"$prg(SAFT) not found
most parts of the GUI are missing!
----
$usage
----
!!Hint:
check PATH environment variable."

    } else {
        set prg(SAFT) $osaft           ;# found
    }
}

set cfg(DESC)   {-- CONFIGURATION internal data storage ----------------------}
set cfg(CDIR)   [file join [pwd] [file dirname [info script]]]
set cfg(EXEC)   -1 ;# count executions, used for object names
    #               # counter also used for number of TABs in $cfg(objN),
    #               # hence with gui-layout=classic # TABs with results of exec
    #               # start at 4 (or 5 with --d*), see create_main_tabs()
set cfg(x--x)   0  ;# each option  will have its own entry (this is a dummy)
set cfg(x++x)   0  ;# each command will have its own entry (this is a dummy)
set cfg(winO)   "" ;# object name of Help   window
set cfg(win-)   "" ;# (reserved for future use)
set cfg(winS)   ".";# object name of main   window (usually not used as just .)
set cfg(winA)   "" ;# object name of About  window
set cfg(winD)   "" ;# object name of Cipher window
set cfg(winF)   "" ;# object name of Filter window
set cfg(winT)   "" ;# (reserved for future use)
set cfg(objN)   "" ;# object name of notebook; needed to add more note TABS
set cfg(objS)   "" ;# object name of status line
set cfg(objT)   "" ;# widget name of button ttyresult
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
    # HELP-LNK          tag assigned to all link texts in text
    # HELP-TOC-*        individual tag for a linked line
    # HELP-LNK-T        tag assigned to top of text
    # HELP-HEAD         tag assigned to all header texts (lines)
    # HELP-HEAD-*       individual tag for a header text
    # HELP-TOC          tag assigned to all lines in table of content
    # HELP-TOC-*        individual tag for a TOC line
    # HELP-REF          tag assigned to all TOC reference
    # HELP-XXX-*
    # HELP-CODE         tag assigned to all code texts

set hosts(0)    ""; # array containing host:port
set results(0)  ""; # contains raw results of prg(SAFT); results(0) is empty

#_____________________________________________________________________________
#_______________________________________________________ filter definitions __|

# arrays created dynamically: f_key f_mod f_len f_bg f_fg f_rex f_un f_fn f_cmt

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
#   - columns *must* be separated by *exactly one* TAB
#   - empty strings in columns must be written as {}
#   - strings *must not* be enclosed in "" or {}
#   - variables must be defined in map above and used accordingly
#   - lines without RegEx (column f_rex contains {}) will not be applied
#------+-------+-------+-------+-------+-------+-------+-------+-------------------------------
# f_key	f_mod	f_len	f_bg	f_fg	f_fn	f_un	f_rex	description of regex
#------+-------+-------+-------+-------+-------+-------+-------+-------------------------------
  no	-regexp	1	{}	{}	{}	0	no\s*(LO|WE|we|ME|HI)	word 'no' followed by LOW|WEAK|MEDIUM|HIGH
# NOTE   no  has no colours, otherwhise it would mix with filters below
# FIXME  no  must be first RegEx in liste here, but still causes problems in toggle_filter
  LOW	-regexp	3	red	{}	{}	0	(LOW|low)	word  LOW   anywhere
  WEAK	-exact	4	red	{}	{}	0	WEAK	word  WEAK  anywhere
  weak	-exact	4	red	{}	{}	0	weak	word  weak  anywhere
 MEDIUM	-regexp	6	yellow	{}	{}	0	(MEDIUM|medium)	word MEDIUM anywhere
  HIGH	-regexp	4	_lGreen	{}	{}	0	(HIGH|high)	word  HIGH  anywhere
 **INFO	-exact	0	_sBlue	{}	{}	0	**INFO	line  **INFO (information from _ME_)
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
    set name [regsub -all {[+]} $str  {Y}]     ;# commands
    set name [regsub -all {[-]} $name {Z}]     ;# options (mainly)
    set name [regsub -all {[^a-zA-Z0-9_]} $name {X}]
    set name "o$name"  ;# first character must be lower case letter
    return $name
}; # _str2obj

proc _notTOC      {str} {
    #? return 0 if string should be part of TOC; 1 otherwise
    if {[regexp {^ *(NOT YET|WYSIW)} $str]} { return 1 }   ;# skip some special strings
    if {[regexp {^ *$} $str]}               { return 1 }   ;# skip empty
    if {[regexp {^(HIGH|MDIUM|LOW|WEAK|SSL|DHE|OWASP)} [string trim $str]]} { return 1 }
    _dbx 4 " no     = »$str«"
    return 0
}; # _notTOC

proc _count_tuples {str} { return  [expr [expr [llength $str] +1] / 2] }
    #? return number of touples in given list

proc pwarn        {txt} { puts stderr "**WARNING: $txt"; return }
    #? output WARNING message

proc perr         {txt} { puts stderr "**ERROR: $txt";   return }
    #? output ERROR message

proc putv         {txt} {
    #? verbose output
    global cfg
    if {$cfg(VERB) <= 0} { return }
    puts stderr "#\[$cfg(ICH)\]:$txt"
    return
}; # putv

proc _ident       {cnt} {
    #? return ident string
    set txt ""
    for {set i 1} {$i <= $cnt} {incr i} {
        set chr " "; # .
        #if {0==[expr $i % 3]} { set chr "|" }
        append txt $chr
    }
    return $txt
}; # _ident

proc _dbx   {level txt} {
    #? debug output (if $level matches $cfg(DEBUG))
    global cfg
    if {! [expr $cfg(DEBUG) & $level]} { return }
    if {$cfg(DEBUG) < 1} { return }
    # [lindex [info level 1] 0]; # would be simple, but returns wrong
    # name of procedure if it was called within []
    # [info frame -1];           # better
    catch { dict get [info frame -1] proc } me; # name of procedure or error
    if {[regexp {not known in dictionary} $me]} { set me "." }; # is toplevel
    puts stderr "#dbx# \[$cfg(ICH)\]$me$txt"
    return
}; # _dbx

proc _trace      {args} {
    #? trace output
    global cfg
    if {0>=$cfg(TRACE)} { return }
    set cnt  [info level]
    set txt  "$args"
    # convert from: {proc_name arg1 arg2} enter
    #           to: proc_name {arg1 arg2} {                     # dumm } for tcl
    set txt  [regsub {^\{} $txt ""]
    set txt  [regsub {^(.[^\s]*)\s*(.*)\}? enter\s*$} $txt "\\1 \{\\2\} \{"]
    if {[regexp {leave$} $txt]} { set txt  [regsub {^([^\s]*).*} $txt "\\1 \}"] }
       # just keep function name from noisy leave message:
       #             {proc_name arg1 arg2} 0 noisy text   -->  proc_name
    puts stderr "#\[$cfg(ICH)\][_ident $cnt]$txt"
    return
    # more lazy mode, not implemented ...
    #set func [lindex $args 0]
    #puts stderr "#\[$cfg(ICH)\][_ident $cnt]$func"
    #return
}; # _trace

proc _trace_add   {cmd} {
    #? initialise Tcl's tracing for given command or widget
    trace add execution $cmd enter _trace
    trace add execution $cmd leave _trace
    return
}; # _trace_add

proc trace_commands  {} {
    #? initialise Tcl's tracing for most of our procs
    append _trace_cmds "[info procs config*] "
    append _trace_cmds "[info procs create*] "
    append _trace_cmds "[info procs osaft*]  "
    append _trace_cmds "[info procs search*] "
    append _trace_cmds "read_images remove_host www_browser show_window "
    append _trace_cmds "gui_init gui_main guitheme_init update_cfg"
        # procs not found by info command before
    foreach _cmd $_trace_cmds {
        if {[regexp "\(create_\(tip\)\)" $_cmd]} { continue }
        _trace_add $_cmd
    }
    return
}; # trace_commands

proc trace_buttons   {} {
    #? initialise Tcl's tracing for all buttons
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
    if {"image" eq $theme} {
       set imgfile [regsub "$cfg(ICH)$" $cfg(ME) "$cfg(IMG)"];   # must be same path
       _dbx 4 " IMG $imgfile"
       if {[file isfile $imgfile]} {
           catch { source $imgfile } error_txt
       } else {
           pwarn "$cfg(IMG) not found; using traditional buttons"
       }
    }
    _dbx 4 " IMG    = [array names IMG]"
    return
}; # read_images

proc update_cfg   {}        {
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
    if {1==[info exists cfg(RCSID)]} {
        # cfg(RCSID) is defined in .o-saft.tcl, warn if old one
        _dbx 4 " RCmin$cfg(RCmin) > RCSID$cfg(RCSID) ?"
        if {$cfg(RCmin) > $cfg(RCSID)} {
            _message warning "$cfg(RC) version $cfg(RCSID)" \
                "converting data to new version ...\n\nplease update $cfg(RC) using 'usr/$cfg(RC)'"
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

# if {1==$cfg(gui-tip)} { # use own tooltip from: http://wiki.tcl.tk/3060?redir=1954

proc guitip_set     {w txt} {
    #? add tooltip message to given widget
    global cfg
    if {1==$cfg(gui-tip)} { # package tooltip not available, use own one
        bind $w <Any-Enter> "after 1000 [list _show_tooltip %W [list $txt]]"
        bind $w <Any-Leave> "destroy %W.balloon"
    } else {
        set txt [regsub {^-} $txt " -"];# texts starting with - cause problems in tooltip::tooltip
        tooltip::tooltip $w "$txt"
    }
    return
}; # guitip_set

proc _show_tooltip  {w txt} {
    if {[eval winfo containing  [winfo pointerxy .]]!=$w} {return}
    set top $w.balloon
    catch {destroy $top}
    toplevel $top -bd 1 -bg black
    wm overrideredirect $top 1
    if {[string equal [tk windowingsystem] aqua]}  {
        ::tk::unsupported::MacWindowStyle style $top help none
    }
    pack [message $top.txt -aspect 10000 -bg lightyellow \
    -font fixed -text $txt]
    set wmx [winfo rootx $w]
    set wmy [expr [winfo rooty $w]+[winfo height $w]]
    wm geometry $top [winfo reqwidth $top.txt]x[
    winfo reqheight $top.txt]+$wmx+$wmy
    raise $top
    return
}; # _show_tooltip

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

proc guitheme_set {w theme} {
    #? set attributes for specified object
    # last part of the Tcl-widgets is key for array cfg_buttons
    _dbx 2 "{$w, $theme}"
    global cfg cfg_buttons IMG
    # text and tip are always configured
    set key [regsub {.*\.([^.]*)$} $w {\1}];# get trailer of widget name
    set val [_get_tipp  $key];  if {"" ne $val} { guitip_set   $w  $val }
    set val [_get_text  $key];  if {"" ne $val} { $w config -text  $val }
    set val [_get_image $key];  if {![info exists IMG($val)]} { set theme "text" }
    _dbx 4 " $w\t-> $key\t$theme\t-> $val"
    if {"text"  eq $theme} {
        set val [_get_color  $key]
        if {"" ne $val} { $w config -bg    $val }
        $w config -image {} -height 1 -relief raised
    }
    if {"image" eq $theme} {
        if {"" ne $val} {
            set h   30
            if {![regexp {^::tk} $IMG($val)]} { set h 20 }
            $w config -image $IMG($val) -relief flat
            $w config -height $h           ;# always set image height
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
    # widget. First build a RegEx which matches all widget names of buttons.
    set rex [join [array names cfg_buttons] "|"]
    set rex [join [list {\.(} $rex {)$}]    "" ]
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
    foreach w [list . objN objS winA winD winF winO] {
        if {"." ne $w} { set w $cfg($w) }
        if {""  eq $w} { continue }
        # now get all children too
        foreach c "$w [info commands $w.*]" {
            if {"" eq $c}  { continue }
            if {2<[regexp -all {\.} $c]} { continue }  ;# only first level
            catch {  $c config -cursor $cursor }       ;# silently discard errors
        }
    }
    return
}; # guicursor_set

proc guistatus_set    {val} {
    #? add text to status line
    global cfg
    if {1==$cfg(quit)} { return }          ;# no GUI update
    $cfg(objS) config -state normal
    $cfg(objS) insert end "$val\n"
    $cfg(objS) see "end - 2 line"
    gui_set_readonly $cfg(objS)
    update idletasks                       ;# enforce display update
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

proc toggle_cfg          {w opt val}      {
    #? use widget config command to change options value
    if {$val ne {}} { $w config $opt $val }
    return 1
}; # toggle_cfg

proc toggle_filter_text  {w tag val line} {
    #? toggle visability of text tagged with name $tag in text widget
    # note that complete line is tagged with name $tag.l (see apply_filter)
    _dbx 4 " $w tag config $tag -elide [expr ! $val]"
    global cfg
    #if {0==$line} {
        #$w tag config $tag   -elide [expr ! $val] ;# "elide true" hides the text
    #}
    if {[regexp {\-(Label|#.KEY)} $tag]} {
        $w tag config $tag   -elide [expr ! $val]  ;# hide just this pattern
        # FIXME: still buggy (see below)
        return
    }
    # FIXME: if there is more than one tag associated with the same range of
    # characters (which is obviously for $tag and $tag.l), then unhiding the
    # tag causes the $tag no longer accessable. Reason yet unknown.
    # Hence we only support hiding the complete line yet.
    $w tag config $tag.l -elide [expr ! $val]
    return
}; # toggle_filter_text

proc toggle_filter_table {w tag val}      {
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

proc toggle_filter       {w tag val line} {
    #? toggle visability of text tagged with name $tag
    _dbx 2 "{$w $tag $val $line}"
    global cfg
    switch $cfg(gui-result) {
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
        if {0 eq $k} { continue }  ;# TODO: == or eq ?
        # extract values from filter table for easy use
        #set key $f_key($k)
        set mod $f_mod($k)
        set len $f_len($k)
        set rex $f_rex($k)
        set fg  $f_fg($k)
        set bg  $f_bg($k)
        set nr  $f_un($k)
        set fn  $f_fn($k)
        if {"" eq $key} { continue }   ;# invalid or disabled filter rules
        if {"" eq $rex} { continue }   ;# -"-
        _dbx 4 " $key : /$rex/ $mod: bg=$bg, fg=$fg, fn=$fn"
        # anf contains start, end corresponding end position of match
        set key [_str2obj [string trim $key]]
        set anf [$w search -all $mod -count end "$rex" 1.0]
        set i 0
        foreach a $anf {
            set e [lindex $end $i]
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
        if {""  ne $fg} { $w tag config HELP-$key -foreground $fg }
        if {""  ne $bg} { $w tag config HELP-$key -background $bg }
        if {"0" ne $nr} { $w tag config HELP-$key -underline  $nr }
        if {""  ne $fn} { $w tag config HELP-$key -font       $fn }
    }
    return
}; # apply_filter_text

proc apply_filter_table {w} {
    #? apply filters for markup in output, data is in table widget $w
    # FIXME: this is ugly code because the RegEx in f_rex are optimised for
    # use in Tcls's text widget, the RegEx must be changed to match the values
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
            if {0 eq $k} { continue }
            # extract values from filter table for easy use
            #set key $f_key($k)
            set mod $f_mod($k) ;# not used here
            set len $f_len($k) ;# not used here
            set rex $f_rex($k)
            set fg  $f_fg($k)
            set bg  $f_bg($k)
            set un  $f_un($k)
            set fn  $f_fn($k)  ;# does not work in tablelist
            if {"" eq $key} { continue }   ;# invalid or disabled filter rules
            if {"" eq $rex} { continue }   ;# -"-
            _dbx 4 " $key : /$rex/ bg=$bg, fg=$fg, fn=$fn"
            # finding the pattern in the  table's cells is not as simple as in
            # texts (see apply_filter_text() above), that's why the RegEx must
            # be applied to the proper column: $col and $matchtxt is needed
            switch -exact $key {
                "no"        { continue }
                "_ME_"      -
                "Label:"    -
                "**WARN"    -
                "**INFO"    -
                "!!Hint"    -
                "== CMT"    -
                "# DBX"     { set col 1; set matchtxt $label }
                "NO"        { set col 2; set matchtxt $value; set rex ^no }
                "YES"       { set col 2; set matchtxt $value }
            }
            set rex [regsub {^(\*\*|\!\!)} $rex {\\\1}]
                # RegEx are designed for Tcl's text search where we have the
                # -exact or -regex option; this RegEx must be converted for
                # use in Tcl's regexp: need to escape special characters
            if {[regexp         ^(A|B|C|D|-?-)$         $key]} { set col 2; set matchtxt $value }
            if {[regexp -nocase ^(LOW|WEAK|MEDIUM|HIGH) $key]} { set col 3; set matchtxt $cmt }
            if {[regexp -nocase -- $rex "$matchtxt"]} {
                if {1==$col} {
                    # if the match is against the first column, colourise the whole line
                    if {"" ne $fg}  { $w rowconfig  $nr      -foreground $fg }
                    if {"" ne $bg}  { $w rowconfig  $nr      -background $bg }
                    if {"" ne $fn}  { $w rowconfig  $nr      -font       $fn }
                   #if {$un ne "0"} { $w rowconfig  $nr      -underline  1   }
                } else {
                    if {"" ne $fg}  { $w cellconfig $nr,$col -foreground $fg }
                    if {"" ne $bg}  { $w cellconfig $nr,$col -background $bg }
                    if {"" ne $fn}  { $w cellconfig $nr,$col -font       $fn }
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
    if {[string length $prg(BROWSER)] < 1} { pwarn [_get_text no_browser]; return }
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
        set e [lindex $end $i]
        set t [string trim [$w get $a "$a + $e c"]]
        set l [string length $t]
        incr i
        $w tag add    $tagname     $a "$a + $e c"
        $w tag add    $tagname-$i  $a "$a + $e c"
        $w tag config $tagname-$i -foreground [_get_color link]
        $w tag bind   $tagname-$i <ButtonPress> "www_browser $t"
        if {0==$cfg(gui-tip)} { tooltip::tooltip $w -tag $tagname-$i "[_get_tipp open_browser] $t" }
            # cannot use guitip_set as we want to bind to $tagname and not $w
    }
    return
}; # bind_browser

proc create_selected   {title val}  {
    #? opens toplevel window with selectable text
    global cfg myX
    global __var   ;# must be global
    set w    .selected
    toplevel $w
    wm title $w "$cfg(TITLE): $title"
    wm geometry  $w 200x50
    pack [entry  $w.choosen  -textvariable __var -relief flat]
    pack [button $w.closewin -command "destroy $w"] -side right -padx $myX(rpad)
    guitheme_set $w.closewin $cfg(gui-button)
    guitip_set   $w.choosen "[_get_tipp choosen] $title"
    set __var "$val"
    return 1
}; # create_selected

proc destroy_window    {w win}      {
    #? wrapper to destroy toplevel window
    #  avoids destroying the window if key was pressed i.e. in an entry widget
    if {$win eq $w} { destroy $win }
    return
}; # destroy_window

proc create_window     {title size} {
    #? create new toplevel window with given title and size; returns widget
    # special handling for windows with title "Help" or "About"
    _dbx 2 "{$title, $size}{"
    global cfg myX
    set this    .[_str2obj $title]
    if {[winfo exists $this]}  { return "" }   ;# do nothing
    toplevel     $this
    wm title     $this "$cfg(TITLE): $title"
    wm iconname  $this "o-saft: $title"
    wm geometry  $this $size
    pack [frame  $this.f1] -fill x -side bottom
    pack [button $this.f1.closewin -command "destroy $this"] -padx $myX(rpad) -side right
    bind $this <Key-q>            "destroy_window %W $this";# see "Key Bindings"
    # TODO: bind should not apply to entry fields
    guitheme_set $this.f1.closewin $cfg(gui-button)
    if {"Help" eq $title || "About" eq $title} { return $this };# FIXME: use configurable texts
    if {[regexp {^Filter} $title]}             { return $this }
    if {[regexp {^Config} $title]}             { return $this }
    if {[regexp {^Settin} $title]}             { return $this }

    # all other windows have a header line and a Save button
    pack [frame  $this.f0    -borderwidth 1 -relief sunken]     -fill x -side top
    pack [label  $this.f0.t  -text $title   -relief flat  ]     -fill x -side left
    pack [button $this.f0.help_me     -command "create_help {$title}"]  -side right
    pack [button $this.f1.saveconfig  -command "osaft_save   $this.f0.t {CFG} 0" ] -side left
        # widget paremeter $tbl for osaft_save is unused here
    guitheme_set $this.f1.saveconfig $cfg(gui-button)
    guitheme_set $this.f0.help_me    $cfg(gui-button)
    _dbx 2 "=$this }"
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
proc create_window:helpcmd  {w cmd} { $w.f0.help_me    config -command $cmd; return }
    #? configure new command for "?" button in created window
proc create_window:savecmd  {w cmd} { $w.f1.saveconfig config -command $cmd; return }
    #? configure new command for "Save" button in created window
proc create_window:noclose  {w}     { destroy $w.f1.closewin;   return }
    #? destroy "Close" button in created window
proc create_window:nohelp   {w}     { destroy $w.f0.help_me;    return }
    #? destroy "?" button in created window
proc create_window:nosave   {w}     { destroy $w.f1.saveconfig; return }
    #? destroy "Save" button in created window

proc create_host  {parent host_nr}  {
    #? frame with label and entry for host:port; $host_nr is index to hosts()
    # must use index to hosts() instead of host itself because the entry widget
    # needs a variable
    _dbx 2 "{$parent, $host_nr}{"
    global cfg hosts myX
    if {$host_nr >= [array size hosts]} {
        set host  ""
    } else {
        set host  $hosts($host_nr)
    }
    _dbx 4 " host=$host, gui-layout=$cfg(gui-layout)"
    # the frame with the entry and button widgets will be created and deleted
    # dynamically, it's difficult to find a unique widget name, hence it will
    # be searched for 
    set nr   0
    set this ${parent}$nr
    while {[winfo exists $this]} { incr nr; set this ${parent}$nr }
        # got new valid widget name
    frame        $this
    grid [label  $this.lh -text [_get_text host]] \
         [entry  $this.eh -textvariable hosts($host_nr)] \
         [button $this.host_del -command "remove_host $this; set hosts($host_nr) {}"] \
         [button $this.host_add -command "create_host {$parent} [array size hosts];"] \

    guitheme_set $this.host_add $cfg(gui-button)
    guitheme_set $this.host_del $cfg(gui-button)
    if {0==$nr} {
        # first line has no {-} but {About}
        grid forget  $this.host_del
        if {"classic" eq $cfg(gui-layout)} {
            grid [button $this.about -command "create_about"] -row 0
            grid config  $this.about -column 4 -sticky e -padx "1 $myX(padx)"
            guitheme_set $this.about $cfg(gui-button)
        }
    }

    grid config  $this.eh -column 1 -sticky ew
    grid columnconfigure    $this 1 -weight 1
    pack $this -fill x -before ${parent}_1
    _dbx 2 "=$this }"
    return $this
}; # create_host

proc remove_host  {parent}          {
    #? destroy frame with label and entry for host:port
    catch {destroy $parent.eh $parent.bp $parent.bm $parent.lh $parent}
    return
}; # remove_host

proc create_text  {parent content}  {
    #? create scrollable text widget and insert given text; returns widget
    _dbx 2 "{$parent, ...}{"
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
    _dbx 2 "=$this }"
    return $this
}; # create_text

proc create_table {parent header}   {
    #? create scrollable table widget with given header lines; returns table widget
    _dbx 2 "{$parent, ...}{"
    set this $parent
    global cfg
    pack [scrollbar $this.x -orient horizontal -command [list $this.t xview]] -side bottom -fill x
    pack [scrollbar $this.y -orient vertical   -command [list $this.t yview]] -side right  -fill y
    pack [tablelist::tablelist $this.t    \
             -exportselection   true      \
             -selectmode        extended  \
             -selecttype        row       \
             -arrowcolor        black     \
             -background        white     \
             -borderwidth       1         \
             -stripebackground  lightgray \
             -arrowstyle      $cfg(tfont) \
             -labelrelief       solid     \
             -labelfont         osaftBold \
             -labelpady         3         \
             -labelcommand      tablelist::sortByColumn -showarrow true \
             -movablecolumns    true      \
             -movablerows       false     \
             -xscrollcommand    [list $this.x set] \
             -yscrollcommand    [list $this.y set] \
             -font              TkFixedFont \
             -spacing             1 \
             -height             25 \
             -width             150 \
             -stretch             2 \
         ] -side left -fill both -expand yes
    # insert header line
    foreach f $header {
        # silently use given keyas text if not defined properly
        if {[catch { set txt [_get_text $f]}]} { set txt $f }
        lappend titles 0 $txt
    }
    $this.t config -columns $titles
    _dbx 2 "=$this.t }"
    return $this.t
}; # create_table

proc create_resulttext  {parent content} {
    #? create scrollable text widget and insert given text; returns widget
    return [create_text $parent $content]
}; # create_resulttext

proc create_resulttable {parent content} {
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
    _dbx 2 "{$parent, ...}{"
    _dbx 16 " content=»$content«"
    global  cfg prg
    set this    $parent.ft
    frame $this
    set table [create_table $this [list t_nr t_label t_value t_comment]]
    # configure columns
    $table columnconfigure 0 -width  3 ;# -hide true ;# line nr
    $table columnconfigure 1 -width 50 ;# label
    $table columnconfigure 2 -width 25 ;# value
    # insert content
    set i 0        ;# count line numbers; for debuging and warning message
    set n 1        ;# add unique number to each line, for initial sorting
    set ssl ""     ;# TODO: ungly hack: need to detect header line with protocol
    set tsize 0    ;# count size of text, for debugging only
    foreach line [split $content "\n"] {
        incr i
        # content consist of lines separated by \n , where each line is a label
        # and a value separated by a tab (and additional spaces for formatting)
        # in tabular context, only label and value is required; no tabs, spaces
        #_dbx 16 " line   = $i, len=[string length $line]"
        if {0>=[string length $line]} { continue } ;# defensive programming
        if {[regexp  {^\s*$}  $line]} { continue } ;# skip empty lines
        #_dbx 16 " line   = $line"
        set nr [format %03d [incr n]]
            # integer must have leading 0, otherwise sorting of tablelist fails
            # no more than 999 lines are expected, may be more with --v --trace
        set stretch 0
        set line [regsub {^(=+)} $line {\1:}]      ;# simulate label: value
        if {[regexp {^[=#]+} $line]} {
            $table insert end [list $nr $line]
            $table togglerowhide end               ;# default hidden
            $table cellconfigure end,0 -stretch 1  ;# FIXME: does not work
            #$table cellattrib end,0 -borderwidth 1 ;# FIXME: not supportet by tablelist
            if {[regexp {Ciphers:\sChecking} $line]} {
                # +cipher header line containing protocol, like:
                # === Ciphers: Checking TLSv12 ===
                set ssl [lindex [split $line " "] 3];# remember current protocol
                #dbx# puts "#dbx# C $ssl"
                set line [regsub -all {=}   $line {}];
                set line [regsub -all {^:}  $line {}];
                set line [regsub -all {^ *} $line {}];
            }
            # tablelist does not support "colspan", hence lines are ignored
            continue
        }
        if {[regexp $prg(SAFT).* $line]} {
            $table insert end [list $nr $line]
            $table togglerowhide end
            $table cellconfigure end,0 -stretch 1  ;# FIXME: does not work
            # tablelist does not support "colspan", hence lines are ignored
            continue
        }
        if {[regexp {:}  $line]} {  # line not from +cipher
            set col2 ""
            set col0 [regsub {^([^:]+):.*}  $line {\1}];# get label
            set col1 [regsub {^[^:]+:\s*}   $line {}]  ;# get value
            # NOTE: there my be values like "No other text ..."
            # these literal text should not match our yes|no condition, hence
            if {[regexp -nocase {^no\s+(alternate name|response sent)} $col1]} {
                set col1 "$cfg(no-match)$col1"         ;# add marker
            }
            if {[regexp -nocase {^(yes|no)} $col1]} {
                # lines from +check
                # split yes|no from rest of text
                set col2 [regsub {^[^\s]+\s+} $col1 {}]
                set col1 [regsub -nocase {^(yes|no)\s.*} $col1 {\1}]
                if {$col1 eq $col2} { set col2 "" };# if there is no col2
            }
            if {[regexp "^$cfg(no-match)" $col1]} {
                # replace marker; space avoids later colouring
                set col1 [regsub "^$cfg(no-match)" $col1 { }]
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
                pwarn "line $i: comment for '$col0' to large (> $cfg(max53)); stripped"
                set col2 "[string range $col2 1 $cfg(max53)] ..\[stripped\].." ;# see cfg(max53)
                # FIXME: need to store orignal text somewhere (not in table)
            }
            set line [list $nr $col0 $col1 $col2]
        } else {
            # lines containing cipher, like:
            #   AES128-SHA256 yes HIGH
            set line [regsub {^[ \t]+} $line {}]   ;# remove trailing spaces
            set line [regsub -all {([ \t])+} $line { }]
            set cols [split $line " "]
            set line "$nr $ssl$cfg(nbsp)$cols"     ;# add nr and protocol
                # quick&dirty hack to uniquely show the protocol where a cipher
                # was used: using the non-breaking space (aka FIGURE SPACE, aka
                # numeric non-breaking space) U+2007 avoids that tcl's tabletab
                # breaks the line into columns at spaces.
                # FIXME: see KNOWN PROBLEMS
        }
        set line [regsub -all \t $line {}] ;# remove tabs in line
        $table insert end $line
        set tsize [expr $tsize + [string length $line]]
    }
    #_dbx 16 " tsize  = $tsize"
    pack $this -side top
    _dbx 2 "=$this }"
    return $this
}; # create_resulttable

proc create_filterhead  {parent key col} {
    #? create a cell for header line in the filter grid
    # note: key must be the index to cfg_texts and cfg_tipps array
    _dbx 2 "{$parent, ...}{"
    set this $parent.$key
    grid [label $this -text [_get_text $key] -relief raised -borderwidth 1 ] -sticky ew -row 0 -column $col
    guitip_set  $this       [_get_tipp $key]
    _dbx 2 "}"
    return
}; # create_filterhead

proc create_filtertext  {parent cmd}    {
    #? create table with filter data
    # TODO: should be replaced by create_filtertable()
    _dbx 2 "{$parent, $cmd}{"
    global cfg
    global f_key f_mod f_len f_bg f_fg f_rex f_un f_fn f_cmt ;# filters
    set this $parent
    # { set header line with descriptions
        create_filterhead $this t_key   0
        create_filterhead $this t_moder 1
        create_filterhead $this t_modee 2
        create_filterhead $this t_chars 3
        create_filterhead $this t_regex 4
        create_filterhead $this t_fg    5
        create_filterhead $this t_bg    6
        create_filterhead $this t_font  7
        create_filterhead $this t_u     8
    # }
    foreach {k key} [array get f_key] { # set all filter lines
        if {0 eq $k} { continue }
        #set key $f_key($k)
        set key [_str2obj [string trim $key]]
        set mod $f_mod($k)
        set len $f_len($k)
        set rex $f_rex($k)
        set fg  $f_fg($k)
        set bg  $f_bg($k)
        set nr  $f_un($k)
        set fn  $f_fn($k)
        if {"" eq $key} { continue }       ;# invalid or disabled filter rules
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
        if {0 eq $k} { continue }
        # FIXME: unfortunately this binding executes immediately, which results
        # in a chooseColor window for each row at startup
        #$this.b$k config -vcmd "set f_bg($k) [tk_chooseColor -title $f_bg(0)]; return 1" -validate focusin
        #$this.s$k config -vcmd "tk fontchooser config -command {set f_fn($k)}; tk_chooseColor -title $f_bg(0)]; return 1" -validate focusin
    }
    grid columnconfigure $this {0 1 2 3 5 6 7 8} -weight 0
    grid columnconfigure $this 4   -minsize 20   -weight 1 ;# minsize does not work
    _dbx 2 "=$this }"
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
    _dbx 2 "{$parent, $cmd}{"
    global cfg
    global f_key f_mod f_len f_bg f_fg f_rex f_un f_fn f_cmt; # filters
    set this $parent
    set table [create_table $this [list t_key t_moder t_modee t_chars t_regex t_fg t_bg t_font t_u ]]
    # configure columns
# TODO: -tooltipaddcommand,
    $table config -columns $titles
    $table columnconfigure 0 -width  10;#
    $table columnconfigure 7 -width  10;#
    # insert lines
    set row -1
    foreach {k key} [array get f_key] { # set all filter lines
        if {0 eq $k} { continue }
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
        # $f_mod($k $f_mod($k)

        foreach col [list 0 3 4 5 6 7] {
            $parent.t cellconfig $row,$col -editable yes -editwindow entry
        }
        $parent.t cellconfig $row,8    -editable yes -editwindow checkbutton
        $parent.t cellconfig $row,0 -fg $f_fg($k) -bg $f_bg($k) -font $f_fn($k)
    }
    _dbx 2 "=$this }"
    return $this
}; # create_filtertable

proc create_filtertab   {parent cmd}    {
    #? create tab with filter data
    _dbx 2 "{$parent, $cmd}{"
    global cfg
    pack [label $parent.text -relief flat -text [_get_tipp tabFILTER]]
    set this $parent.g
    pack [frame $this] -side top -expand yes -fill both
    set tab [create_filtertext  $this $cmd].t
    catch { # silently ignore if systems has no fontchooser (i.e. Mac OS X)
        tk fontchooser config -command {create_selected [_get_text win_font]}; # what to do with selection
            # there is no tk_fontchooser, but tk::fontchooser or tk fontchooser
        pack [button $parent.tkfont  -command {tk fontchooser show}] -side right
        guitheme_set $parent.tkfont $cfg(gui-button)
    }
    pack [button $parent.tkcolor -command {create_selected [_get_text win_colour] [tk_chooseColor]} ] -side right
    guitheme_set $parent.tkcolor $cfg(gui-button)
    _dbx 2 "}"
    return
}; # create_filtertab

proc create_filterwin   {}  {
    #? create window with filter data
    #  used for --gui-layout=tablet only
    _dbx 2 "{}{"
    global myX
    set win [create_window  [_get_text win_filter] $myX(geoF)]
    if {"" eq $win} { return }
    create_filtertab  $win {FIL}
    _dbx 2 "}"
    return
}; # create_filterwin

proc create_filter      {parent cmd}    {
    #? create new window with filter commands for exec results; store widget in cfg(winF)
    _dbx 2 "{$parent, $cmd}{"
    global cfg f_key f_bg f_fg f_cmt filter_bool myX
    if {[winfo exists $cfg(winF)]}  { show_window $cfg(winF); return }
    set obj $parent;    # we want to have a short variable name
    set geo [split [winfo geometry .] {x+-}]
    set myX(geoF) +[expr [lindex $geo 2] + [lindex $geo 0]]+[expr [lindex $geo 3]+100]
        # calculate new position: x(parent)+width(parent), y(parent)+100
        # most window managers are clever enough to position window
        # correctly if calculation is outside visible (screen) frame
    set cfg(winF) [create_window "[_get_text win_filter]:$cmd" $myX(geoF)]
        # FIXME: only one variable for windows, need a variable for each window
        #        workaround see osaft_exec
    set this $cfg(winF)
    _dbx 2 " parent: $obj | $cmd | $myX(geoF)"
    pack [frame $this.f -relief sunken -borderwidth 1] -fill x
    pack [label $this.f.t -relief flat -text [_get_text c_toggle]] -fill x
    pack [checkbutton $this.f.c -text [_get_text hideline] -variable filter_bool($obj,line)] -anchor w
    guitip_set  $this.f.c [_get_tipp hideline]
    gui_set_readonly $this.f.c
    foreach k [lsort -integer [array names f_key]] {
        # the Tclisch way to go through the array would simply be:
        #   foreach {k txt} [array get f_key] { ... }
        # which assign the index to $k and all the rest to $txt
        # but the array should be processed in the sequence as it was defined,
        # hence the more cumbersome way with lsort is used which then needs to
        # get the key additionally
        if {0 eq $k} { continue }
        set txt $f_key($k)
        set bg  $f_bg($k)
        set fg  $f_fg($k)
        set key [_str2obj [string trim $txt]]
        _dbx 2 " $k\t$txt\t$obj"
        set filter_bool($obj,HELP-$key) 1;  # default: checked
        pack [checkbutton $this.x$key \
                -text $txt -variable filter_bool($obj,HELP-$key) \
                -command "toggle_filter $obj HELP-$key \$filter_bool($obj,HELP-$key) \$filter_bool($obj,line);" \
             ] -anchor w
            # note: checkbutton value passed as reference
        # TODO: following "-fg white" makes check in checkbox invisible
        if {"" ne $fg}  { $this.x$key config -fg $fg } ;# Tk is picky ..
        if {"" ne $bg}  { $this.x$key config -bg $bg } ;# empty colour not allowd
        guitip_set $this.x$key "[_get_tipp show_hide] $f_cmt($k)"
	# FIXME: hardcoded uncheck, because not visible by default, see create_resulttable
        if { [regexp {^(==|o-saft)} $txt]} {
            set filter_bool($obj,HELP-$key) 0
        }
    }
    _dbx 2 "}"
    return
}; # create_filter

proc create_configtab   {parent cmd}    {
    #? create tab with config data
    _dbx 2 "{$parent, $cmd}{"
    global cfg
    set this $parent.or
    pack [frame $this] -fill x -padx 5 -anchor w
    pack [label $this.l -text [_get_text gui_layout] -width 20] \
         [radiobutton $this.s$cmd -variable cfg(gui-result) -value "text"  -text "text" ] \
         [radiobutton $this.t$cmd -variable cfg(gui-result) -value "table" -text "table"] \
         -padx 5 -anchor w -side left
    guitip_set  $this [_get_tipp "layout"]
    set this $parent.ob
    pack [frame $this] -fill x -padx 5 -anchor w
    pack [label $this.b -text [_get_text gui_button] -width 20] \
         [radiobutton $this.j$cmd -variable cfg(gui-button) -value "text"  -text "text" ] \
         [radiobutton $this.i$cmd -variable cfg(gui-button) -value "image" -text "image"] \
         -padx 5 -anchor w -side left
    guitip_set  $this [_get_tipp "img_txt"]
    set this $parent.oc
    pack [frame  $this] -fill x -padx 5 -anchor w
    pack [button $this.v$cmd -command "create_main tablet" -text [_get_text menu_mode]] \
         -side left
    guitip_set  $this [_get_btn_tip menu_mode]
    _dbx 2 "}"
    return
}; # create_configtab

proc create_configwin   {}  {
    #? create window with gui config data
    #  used for --gui-layout=tablet only
    _dbx 2 "{}{"
    global myX
    set win [create_window  [_get_text win_config] $myX(geoC)]
    if {"" eq $win} { return }
    create_configtab  $win {CFG}
    _dbx 2 "}"
    return
}; # create_configwin

proc create_tooltab     {parent cmd}    {
    #? create tab with tool config data
    _dbx 2 "{$parent, $cmd}{"
    global cfg prg

    set  this $parent.c
    pack [frame $this   -relief sunken -borderwidth 1] -fill x -anchor w
    pack [label $this.t -relief flat -text "Self:"] -fill x -anchor w
    foreach var [list ME DIR O-Saft RC IMG] {
        set  this $parent.cfg_$var
        pack [frame $this] -fill x -padx 5 -anchor w
        pack [label $this.l -text "cfg($var)" -width 15] \
             [entry $this.e -textvariable cfg($var) -width 33] \
             -padx 5 -anchor w -side left
    }

    set  this $parent.r
    pack [frame $this   -relief sunken -borderwidth 1] -fill x -anchor w
    pack [label $this.t -relief flat -text [_get_text cfg_regex]] -fill x -anchor w
    foreach var [list rexOPT-cfg rexOPT-help rexOUT-head rexOUT-int rexOUT-cmd rexOUT-hide rexOUT-show] {
        set  this $parent.regex_$var
        pack [frame $this] -fill x -padx 5 -anchor w
        pack [label $this.l -text "prg($var)" -width 15] \
             [entry $this.e -textvariable prg($var) -width 33] \
             -padx 5 -anchor w -side left
    }
    # prg(Ocmd) prg(Oopt)

    set  this $parent.p
    pack [frame $this   -relief sunken -borderwidth 1] -fill x -anchor w
    pack [label $this.t -relief flat -text [_get_text cfg_progs]] -fill x -anchor w
    foreach var [list SAFT INIT PERL BROWSER TKPOD POST] {
        set  this $parent.progs_$var
        pack [frame $this] -fill x -padx 5 -anchor w
        pack [label $this.l -text "prg($var)" -width 15] \
             [entry $this.e -textvariable prg($var) -width 33] \
             -padx 5 -anchor w -side left
    }

    set  this $parent.d
    pack [frame $this   -relief sunken -borderwidth 1] -fill x -anchor w
    pack [label $this.t -relief flat -text [_get_text cfg_docker]] -fill x -anchor w
    foreach var [list docker-id docker-tag] {
        set  this $parent.docker_$var
        pack [frame $this] -fill x -padx 5 -anchor w
        pack [label $this.l -text "prg($var)" -width 15] \
             [entry $this.e -textvariable prg($var) -width 33] \
             -padx 5 -anchor w -side left
    }
    guitip_set  $this.e [_get_tipp docker-id]
    _dbx 2 "}"
    return
}; # create_tooltab

proc create_toolwin     {}  {
    #? create window with tool config data
    #  used for --gui-layout=tablet only
    _dbx 2 "{}{"
    global myX
    set win [create_window  [_get_text win_tool] $myX(geoT)]
    create_window:nosave  $win    ;# no "Save" button needed here
    if {"" eq $win} { return }
    create_tooltab    $win {CFG}
    _dbx 2 "}"
    return
}; # create_toolwin

proc create_ciphers     {}  {
    #? create new window with Cipher Suites; store widget in cfg(winD)
    # SEE Cipher:text (in o-saft-man.pm) for expected data
    _dbx 2 "{}{"
    global cfg myX
    if {[winfo exists $cfg(winD)]}  { show_window $cfg(winD); return }
    set cfg(winD) [create_window [_get_text win_cipher] $myX(geoD)]
    set data  [osaft_ciphers]]
    # extract column headers from data and convert data to array
    set head    1
    set row     ""
    set header  ""
    set content ""
    foreach l [split $data "\r\n"] {
        if { [regexp {^\s*$} $l]} { continue }
        if { [regexp {^[=#]} $l]} { continue }
        set l [string trim $l]
        set l [regsub {\t\t} $l "\t"]  ;# squeeze TABs
        set key  [lindex [split $l "\t"] 0]
        set val  [lindex [split $l "\t"] 1]
        if { [regexp {^0x}   $key]} {
            if {0 <  [llength $row]} { append content "$row\n" }
            if {0 >= [llength $header]} {
                set header [list "Hex Code" "Security" "Cipher Suite"]
            } else {
                set head 0
            }
            set name [lindex [split $l "\t"] 2]
            set row  [list $key $val $name]
            continue
        }
        if {0 < $head} {
            lappend header [regsub {\s*:\s*$} $key ""];# remove trailing spaces
        }
        lappend row $val
    }
    set table [create_table $cfg(winD) $header]
    $table columnconfigure  0 -width 14 ;# hex
    $table columnconfigure  1 -width  7 ;# sec
    $table columnconfigure  2 -width 30 ;# suite name
    $table columnconfigure  3 -width 30 ;# OpenSSL name
    $table columnconfigure  6 -width  7 ;# openssl
    $table columnconfigure  7 -width  7 ;# ssl
    $table columnconfigure  8 -width  8 ;# keyx
    $table columnconfigure  9 -width  7 ;# auth
    $table columnconfigure 10 -width 15 ;# enc
    foreach row [split $content "\n"] { $table insert end $row }
    _dbx 2 "}"
    return
}; # create_ciphers

proc create_about       {}  {
    #? create new window with About text; store widget in cfg(winA)
    #  Show the text starting with  #?  from this file.
    _dbx 2 "{}{"
    global cfg myX
    if {[winfo exists $cfg(winA)]}  { show_window $cfg(winA); return }
    set cfg(winA) [create_window [_get_text win_about] $myX(geoA)]
    set txt [create_text $cfg(winA) [osaft_about "ABOUT"]].t
    $txt config -bg [_get_color osaft]

    # search for section headers and mark them bold
    set anf [$txt search -regexp -nolinestop -all -count end {^ *[A-ZÄÖÜß ]+$} 1.0]
    set i 0
    foreach a $anf {
        set e [lindex $end $i]
        $txt tag add sektion  $a "$a + $e char"
        incr i
    }
    $txt tag config sektion -font osaftBold

    # bind buttons and keys
    bind_browser $txt ABOUT-URL
    bind  $txt <KeyPress>   "search_view $txt %K"
    _dbx 2 "}"
    return
}; # create_about

proc create_pod   {viewer sect}  {
    #? create new window with complete help using external viewer
    # for advantages and disadvantages please see usr/.o-saft.tcl
    _dbx 2 "{$viewer, $sect}{"
    global cfg myX
    set pod $cfg(POD)
    if ![info exists $pod] { set pod "doc/$pod" }
    # TODO: does probably not working on Windows
    putv  " exec {*}$viewer $pod -geo $myX(geoO) & "
    catch { exec {*}$viewer $pod -geo $myX(geoO) & }
    _dbx 2 "}"
    return
}; # create_pod

proc create_help  {sect} {
    #? create new window with complete help text; store widget in cfg(winO)
    #? if  sect  is given, jump to this section
    _dbx 2 "{$sect}{}" ;# no "_dbx 2"  at very end, because there are early returns
    global cfg myX prg search

    if {1==[info exists prg(TKPOD)]} {
        if {$prg(TKPOD) ne "O-Saft"} {  # external viewer specified, use it ...
            create_pod $prg(TKPOD) $sect
            return
        }
    }

    # uses plain text help text from "o-saft.pl --help"
    # This text is parsed for section header line (all capital characters)
    # which will be used as Table of Content and inserted before the text.
    # All references to this sections are clickable.
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
    guitheme_set $this.f1.help_home   $cfg(gui-button)
    guitheme_set $this.f1.help_prev   $cfg(gui-button)
    guitheme_set $this.f1.help_next   $cfg(gui-button)
    guitheme_set $this.f1.help_help   $cfg(gui-button)
    guitheme_set $this.f1.helpreset   $cfg(gui-button)
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

    # FIXME (2020): all following code for markup needs to be redisigned, as
    # there are to many missing matches (mainly +CMD and --OPTION)  and some
    # matches, which result in wrong markup (i.e. --OPTION in a header line)

    _dbx 4 " 3. search for section head lines, mark them and add (prefix) to text"
    set anf [$txt search -regexp -nolinestop -all -count end {^ {0,5}[A-Z][A-Za-z_0-9? '()=+,:.-]+$} 1.0]
    #dbx# puts "3. $anf\n$end"
    set i 0
    foreach a $anf {
        set e [lindex $end $i]
        set t [$txt get $a "$a + $e c"]        ;# don't trim, need leading spaces
        set l [string length $t]
        incr i
        _dbx 4 " 3. HEAD: $i\t$t"
        if {[regexp { - } $t]}  { continue }   ;# skip glossar lines
        if {[_notTOC $t]}       { continue }   ;# skip some special strings
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
    #_dbx 4 "TOC:[$txt get 1.0 end]"
    set nam [$txt search -regexp -nolinestop {^NAME$} 1.0]; # only new insert TOC
    if {"" eq $nam} {
        _dbx 4 " 3. no text available"         ;# avoid Tcl errors
        return
    }

    _dbx 4 " 4. search for all references to section head lines in TOC and add click event"
    # NOTE: used RegEx must be similar to the one used in 1. above !!
    set anf [$txt search -regexp -nolinestop -all -count end { *[A-Za-z_? '()=,:.-]+( |$)} 3.0 $nam]
    #dbx# puts "4. $anf\n$end"
    set i 0
    foreach a $anf {
        set e [lindex $end $i]
        set t [$txt get $a "$a + $e c"]
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
        set e [lindex $end $i]
        set t [$txt get $a "$a + $e c"]
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
    set anf [$txt search -regexp -nolinestop -all -count end { [-+]-?[a-zA-Z0-9_=+-]+([., )]|$)} 3.0]
    # NOTE: above RegEx does not match  +CMD  or  --OPTION  if they are not
    #       prefixed with at least two spaces (reason unknown).
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
    # head line. This is due to the RegEx in "text search ...",  which doesn't
    # allow spaces. # FIXME:


    # _dbx "############### {\n[$txt get 0.0 end]\n############### }\n"
    set i 0
    foreach a $anf {
        set line_nr  [regsub {[.][0-9]*} $a ""]        ;# get line number from $a
        set line_txt [$txt get $line_nr.1 $line_nr.end];# get full text in the line
        set e [lindex $end $i]
        set l [$txt get "$a - 2 c" "$a + $e c + 1 c"]  ;# one char more, so we can detect head line
        set t [string trim [$txt get $a "$a + $e c"]]
        set r [regsub {[+]} $t {\\+}];  # need to escape +
        set r [regsub {[-]} $r {\\-}];  # need to escape -
        set r [regsub {[)]} $r {\\)}];  # need to escape )
        set name [_str2obj [string trim $t]]
        _dbx 4 " 5. LNK: $i\tHELP-LNK-$name\t$t"
        if {[regexp {^\s*[+|-]} $line_txt] && [regexp -lineanchor "\\s\\s+$r$" $l]} {
            # these matches are assumed to be the header lines
            $txt tag add    HELP-LNK-$name $a "$a + $e c"
            $txt tag add    HELP-LNK       $a "$a + $e c"
        } else {
            # these matches are assumed references
            $txt tag add    HELP-LNK-$i $a "$a + $e c - 1 c" ;# do not markup spaces
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
        set e [lindex $end $i]
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
        _dbx 4 " 7. CODE: $i\tHELP-CODE\t'$t'" ;# add quotes in debug output
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
    #_dbx 8 " TAGS: [$txt tag names]";# huge output!!
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
    _dbx 2 "{$parent, »$title«}{"
    set name [_str2obj $title]
    set this $parent.$name
    set alt  0
    if {[regexp {^\(} $title]} { set alt 1 }   ;# don't use (, but next charcter
    frame       $this
    $parent add $this  -text $title -underline $alt
    _dbx 2 "=$this }"
    return $this
}; # create_note

proc create_tab   {parent layout cmd content} {
    #? create new TAB in .note and set focus for it; returns text widget in TAB
    _dbx 2 "{$parent, $layout, $cmd, ...}{"
    _dbx 4 " content=»$content«"
    global cfg
    set tab [create_note $parent "($cfg(EXEC)) $cmd"]
    switch $layout {
        text    { set w [create_resulttext  $tab $content].t }
        table   { set w [create_resulttable $tab $content].t }
    }
        # ugly hardcoded .t from .note
    pack [button $tab.saveresult -command "osaft_save $w {TAB} $cfg(EXEC)"] \
         [button $tab.ttyresult  -command "osaft_save $w {TTY} $cfg(EXEC)"    ] \
         [button $tab.filter     -command "create_filter $w $cmd"    ] \
         -side left
    pack [button $tab.closetab   -command "destroy $tab"] -side right
   set cfg(objT) $tab.ttyresult
    guitheme_set $tab.closetab   $cfg(gui-button)
    guitheme_set $tab.saveresult $cfg(gui-button)
    guitheme_set $tab.ttyresult  $cfg(gui-button)
    guitheme_set $tab.filter     $cfg(gui-button)
    $cfg(objN) select $tab
    _dbx 2 "=$tab }"
    return $w
}; # create_tab

proc create_cmd   {parent title} {
    #? create button to run O-Saft command; returns widget
    _dbx 2 "{$parent, »$title«}{"
    global cfg
    set name [regsub {^\+} $title {cmd}]   ;# keys start with cmd instead of +
    set this $parent.$name
    pack [button $this -text $title -command "osaft_exec $parent $title"] -side left
    guitheme_set $this $cfg(gui-button)
    _dbx 2 "=$this }"
    return $this
}; # create_cmd

proc create_opt   {parent title} {
    #? create checkbutton for O-Saft options; returns widget
    _dbx 2 "{$parent, »$title«}{"
    global cfg
    set name [regsub {^--} $title {cmd}]   ;# keys start with cmd instead of +
    set this $parent.$name
    pack [checkbutton $this -text $title -variable cfg($title)] -side left -padx 5
    guitip_set   $this [_get_tipp $title]
    _dbx 2 "=$this }"
    return $this
}; # create_opt

proc create_win   {parent title cmd} {
    #? create window for commands and options
    #  creates one button for each line returned by: o-saft.pl --help=opt|commands
    # title must be string of group of command or options
    _dbx 2 "{$parent, »$title« $cmd}{"
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
        # also  lib/Doc/Data.pm  and  lib/Doc/help.txt
        # Note that "Discrete Commands ..." in cfg(HELP) are missing and have
        # no description; must use that from cfg(CMDS).

    set last_key "";# remember last option
    set last_obj "";# remember last entry widget
    set values   {};# collected values of last option
    set skip 1     ;# skip data until $title found
    foreach l [split $data "\r\n"] {
        set dat [string trim $l]
        if {[regexp $prg(rexOUT-cmd) $dat]} { set skip 1 };# next group starts
        if {"$title" eq "$dat"} {   # FIXME: scary comparsion, better use RegEx
            # title matches: create a window for checkboxes and entries
            set skip 0
            _dbx 4 " create window: $win »$dat«"
            set dat [string toupper [string trim $dat ] 0 0]
            set win [create_window $dat ""]
            if {"" eq $win} { return }     ;# do nothing, even no: show_window $this
            set this $win.g
            frame $this                    ;# frame for grid
            continue
        }
        if {1==$skip}                        { continue }
        #dbx# puts "DATA $dat"
        # skipped general
        if {"" eq $dat}                      { continue }
        if {[regexp $prg(rexOUT-head) $dat]} { continue }  ;# ignore header lines
        # skipped commands
        if {[regexp $prg(rexCMD-int)  $dat]} { continue }  ;# internal use only
        # skipped options
       #if {"OPTIONS" eq $dat}               { continue }
        if {[regexp $prg(rexOPT-help) $dat]} { continue }
        if {[regexp $prg(rexOUT-int)  $dat]} { continue }  ;# use other tools for that

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
        if {0==[regexp {=} $dat]} {
            #dbx# puts "create_win: check: $this.$name.c -variable cfg($dat)"
            pack [checkbutton $this.$name.c -text $dat -variable cfg($dat)]  -side left -anchor w -fill x
        } else {
            regexp $prg(rexOPT-cfg) $l dumm idx val    ;# --idx=val --> --idx val
            if {$last_key eq $idx} { lappend values $val; continue };# ignore repeated options, but keep value
            if {[winfo exists $last_obj]} {
                set txt "<text>"
                if {[llength $values] > 0} { set txt [join $values { | }] }
                guitip_set $last_obj "[_get_tipp possible_values] $txt";# $tip may containing collected values
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
        #if {$col > $max} { incr row; set col 0 }  ;# horizontal sorting
        if {$row > $rows} { incr col; set row 0 }  ;# vertical sorting

        grid config $slave -row $row -column $col -padx 8
        #incr col   ;# horizontal
        incr row   ;# vertical
    }
    _dbx 2 "}"
    return
}; # create_win

proc create_buttons     {parent cmd} {
    #? create buttons to open window with commands or options
    #  creates one button for header line returned by: o-saft.pl --help=opt|commands
    #  cmd must be "OPT" or "CMD"
    _dbx 2 "{$parent, $cmd}{"
    global cfg prg
    set data $cfg(OPTS)
    _dbx 4 " gui-layout=$cfg(gui-layout)"
    switch $cmd {
      "CMD" { # expected format of data in $cfg(CMDS) and $cfg(OPTS) see create_win() above
              set data $cfg(CMDS)
            }
      "OPT" { # add options for o-saft.tcl itself
            }
      default { pwarn "create_buttons called with wrong command »$cmd«"; return }
    }
    if {"tablet" ne $cfg(gui-layout)} {
        set txt  [_get_tipp "tab$cmd"]     ;# tabCMD and tabOPT
        pack [label  $parent.o$cmd -text $txt ] -fill x -padx 5 -anchor w -side top
    }
    #_dbx 4 "$data"
    foreach l [split $data "\r\n"] {
        set txt [string trim $l]
        if {0==[regexp $prg(rexOUT-cmd)  $txt]} { continue }   ;# buttons for Commands and Options only
        if {0!=[regexp $prg(rexOUT-hide) $txt]} { continue }   ;# we do not support these options in the GUI
        # skipped general
        if {"" eq $txt}                      { continue }
        if {[regexp $prg(rexOUT-head) $txt]} { continue }      ;# header or Warning
        if {"OPTIONS" eq $txt}               { continue }
        # remove noicy prefix and make first character upper case
        set dat  [string toupper [string trim [regsub {^(Commands|Options) (to|for)} $txt ""]] 0 0]
        set name [_str2obj $txt]
        set this $parent.$name
        _dbx 4 " $name {$txt}"
        if {"tablet" eq $cfg(gui-layout)} {
            $parent add command -label $dat -command "create_win .$name {$txt} $cmd"
        } else {
            pack [frame  $this] -anchor c -padx 10 -pady 2
            pack [button $this.b -text $dat -width 58 -command "create_win .$name {$txt} $cmd" -bg [_get_color button] ] \
                 [button $this.help_me -command "create_help {$txt}" ] \
                   -side left
            guitheme_set $this.help_me $cfg(gui-button)
            guitip_set   $this.b [_get_tipp settings]
    
            # argh, some command sections are missing in HELP, then disable help button
            if {1==[regexp $prg(rexOUT-show) $txt]} { $this.help_me config -state disable }
        }
    }
    _dbx 2 "=$parent }"
    return $parent
}; # create_buttons

proc create_main_menu          {parent w} {
    #? create frame with main menu, quick commands and quick options menu
    #  used for --gui-layout=tablet only
    #.       +---------------------------------------------------------------+
    #.       | ☰  Cmd  Opt                                                   |
    #.       +---------------------------------------------------------------+
    #   ☰  Cmd  Opt  are Tcl menus
    #
    _dbx 2 "{$parent, $w}{"
    global cfg prg myX
    set menu_type menubar  ;# FIXME: not yet implemented due to improper widget names
    set menu_type normal
    # on Mac OS X not yet used: .menubar.apple .menubar.window .menubar.help
    switch $menu_type {
        menubar { set w ""         ;  set packman pack }
        normal  { set w $parent.$w ;  set packman grid;
                  pack [frame   $w -bg black ] -fill x -expand yes
                  lappend cfg(guiwidgets) $w   ;# important! needs to be removed too
                }
    }
    # create menu line with button for: Menu, Commands and Options
    set w_menu $w.main.m
    set w_cmds $w.cmds.m
    set w_opts $w.opts.m
    set w_conf $w.conf.m
    lappend cfg(guimenus) $w_menu $w_cmds $w_opts
    $packman \
         [menubutton $w.main -text [_get_text menu_menu] -menu $w_menu -bg black -fg [_get_color menu_menu] -borderwidth 0] \
         [menubutton $w.cmds -text [_get_text menu_cmd ] -menu $w_cmds -bg black -fg [_get_color menu_cmd ]  -borderwidth 0 -width 5] \
         [menubutton $w.opts -text [_get_text menu_opt ] -menu $w_opts -bg black -fg [_get_color menu_opt ]  -borderwidth 0 -width 5] \
         [menubutton $w.conf -text [_get_text menu_cfg ] -menu $w_conf -bg black -fg [_get_color menu_cfg ]  -borderwidth 0 -width 5]
    guitip_set   $w.main [_get_tipp menu_menu]
    guitip_set   $w.cmds [_get_tipp menu_cmd ]
    guitip_set   $w.opts [_get_tipp menu_opt ]
    guitip_set   $w.conf [_get_tipp menu_cfg ]

    # create ☰  menu
    menu $w_menu -type $menu_type  ;# complete menu
    $w_menu add cascade -label [_get_text menu_cmds] -menu $w_menu.commands
    $w_menu add cascade -label [_get_text menu_opts] -menu $w_menu.options
    $w_menu add cascade -label [_get_text menu_conf] -menu $w_menu.configs
    $w_menu add command -label [_get_text menu_load] -command "osaft_load {_LOAD}"
    $w_menu add separator
    $w_menu add command -label [_get_text menu_list] -command "create_ciphers"
    $w_menu add command -label [_get_text menu_uber] -command "create_about"
    $w_menu add command -label [_get_text menu_help] -command "create_help {}"
    $w_menu add command -label [_get_text menu_exit] -command "exit"

    # create Opt menu
    menu $w_opts -type $menu_type
    foreach opt $prg(Oopt) {
         $w_opts add checkbutton -label $opt -variable cfg($opt) -indicatoron yes
    }
    # create Cmd menu
    menu $w_cmds -type $menu_type
    foreach cmd "Start $prg(Ocmd)" {
         $w_cmds add command    -label $cmd -command "osaft_exec $w.fc $cmd"
    }
    # create Config menu
    menu $w_conf -type $menu_type
    $w_conf add command -label [_get_text menu_filt] -command "create_filterwin"
    $w_conf add command -label [_get_text menu_conf] -command "create_configwin"
    if {0<$cfg(DEBUG)} {
    $w_conf add command -label [_get_text menu_prog] -command "create_toolwin"
    }
    $w_conf add command -label [_get_text menu_mode] -command "create_main classic"
    $w_conf clone $w_menu.configs

    # create submenus for ☰  , Cmd  and  Opt  menu
    menu $w_menu.commands          ;# All Commands menu
    create_buttons $w_menu.commands {CMD}
    $w_menu.commands clone $w_cmds.cmds
    $w_cmds add cascade -label [_get_text menu_cmds] -menu $w_cmds.cmds

    menu $w_menu.options           ;# All Options menu
    create_buttons $w_menu.options  {OPT}
    $w_menu.options add separator
    $w_menu.options add command -label [_get_text menu_rsave] -command {osaft_save "" "CFG" 0}
    $w_menu.options add command -label [_get_text menu_reset] -command {osaft_reset; osaft_init;}
    $w_menu.options clone $w_opts.opts
    $w_opts add cascade -label [_get_text menu_opts] -menu $w_opts.opts

    # {1==$cfg(docker)}
    if {[regexp {\-docker$} $prg(SAFT)]} {
# TODO: add to options tab, see create_main_quick_options()
         set cmd "docker_status"
# TODO:  pack [entry $w.dockerid -textvariable prg(docker-id) -width 12] -anchor w
# TODO:  guitip_set  $w.dockerid [_get_tipp docker-id]
    }

    # FIXME: menus are shown "tearoff" at position 0+0
    # FIXME: binding must not be at entry widget
    # hence disabled
    # bind . <Key-m>  "$w_menu invoke 0"
    # bind . <Key-c>  "$w_cmds invoke 0"
    # bind . <Key-o>  "$w_opts invoke 0"
    # bind . <Key-s>  "$w_conf invoke 0"

    _dbx 2 "=$w.main }"
    return $w.main
}; # create_main_menu

proc create_main_host_entries  {parent w} {
    #? create host entries in main window
    # add hosts from command-line; line  with  +  and  -  or  !  button
    _dbx 2 "{$parent, $w}{"
    global cfg hosts
    set w $parent.$w
    pack [frame ${w}_1]            ;# create dummy frame to keep create_host() happy
    lappend cfg(guiwidgets) ${w}_1 ;# required in remove_main()
    foreach {i host} [array get hosts] {    # display hosts
        if {5 < $i} { pwarn "only 6 hosts possible; »$host« ignored"; continue }
        lappend cfg(guiwidgets) [create_host $w $i]
    }
    _dbx 2 "=$w }"
    return $w
}; # create_main_host_entries

proc create_main_quick_buttons {parent w} {
    #? create command buttons for simple commands and help
    _dbx 2 "{$parent, $w}{"
    global prg myX
    set w   $parent.$w
    pack [frame     $w] -fill x
    pack [button    $w.cmdstart   -command "osaft_exec $w.fc {Start}"] -side left -padx 11
    foreach b $prg(Ocmd) {
        create_cmd  $w $b
    }
    pack [button    $w.loadresult -command "osaft_load {_LOAD}"] -side left  -padx 11
    pack [button    $w.help       -command "create_help {}"]     -side right -padx $myX(padx)
    _dbx 2 "=$w }"
    return $w
}; # create_main_quick_buttons

proc create_main_quick_options {parent w} {
    #? create option checkboxes for simple access
    _dbx 2 "{$parent, $w}{"
    global prg
    set w   $parent.$w
    pack [frame     $w] -fill x
    pack [label     $w.ol -text " "] -side left -padx 11
    foreach b $prg(Oopt) {
        create_opt  $w $b
    }
    if {[regexp {\-docker$} $prg(SAFT)]} {
        pack [entry $w.dockerid -textvariable prg(docker-id) -width 12] -anchor w
        guitip_set  $w.dockerid [_get_tipp docker-id]
    }
    _dbx 2 "=$w }"
    return $w
}; # create_main_quick_options

proc create_main_note          {parent w} {
    #? create notebook object and set up Ctrl+Tab traversal
    #  used for --gui-layout=classic (and version < 1.254 )
    _dbx 2 "{$parent, $w}{"
    global cfg
    set w   $parent.$w
    set cfg(objN)   $w
    ttk::notebook   $w -padding 5
    ttk::notebook::enableTraversal $w
    pack $w -fill both -expand 1
    _dbx 2 "=$w }"
    return $w
}; # create_main_note

proc create_main_tabs          {parent w} {
    #? create notebook object and set up Ctrl+Tab traversal
    #  used for --gui-layout=classic (and version < 1.254 )
    _dbx 2 "{$parent, $w}{"
    global cfg
    set w   $parent.$w
    # create TABs: Command and Options
    set tab_cmds    [create_note $w [_get_text win_cmds  ]]
    set tab_opts    [create_note $w [_get_text win_opts  ]]
    set tab_filt    [create_note $w [_get_text win_filter]]
    set tab_conf    [create_note $w [_get_text win_config]]
    create_buttons    $tab_cmds {CMD}  ;# fill Commands pane
    create_buttons    $tab_opts {OPT}  ;# fill Options pane
    create_filtertab  $tab_filt {FIL}  ;# fill Filter pane
    create_configtab  $tab_conf {CFG}  ;# fill Config pane
    set cfg(EXEC) 3
    if {0<$cfg(DEBUG)} {
       set tab_tool [create_note $w [_get_text win_tool]]
       create_tooltab $tab_tool {PRG}  ;# fill Settings pane
       incr cfg(EXEC)
    }
    # add Save and Reset button in Options pane
    pack [button    $tab_cmds.saveconfig -command {osaft_save "" {CFG} 0} ] -side left
    pack [button    $tab_opts.saveconfig -command {osaft_save "" {CFG} 0} ] -side left
    pack [button    $tab_opts.reset      -command {osaft_reset; osaft_init;}]      -side left
    pack [button    $tab_cmds.reset      -command {osaft_reset; osaft_init;}]      -side left
    _dbx 2 "=$w }"
    return $w
}; # create_main_tabs

proc create_main_status_line   {parent w} {
    #? create status line
    _dbx 2 "{$parent, $w}{"
    global cfg myX
    set w   $parent.$w
    set cfg(objS)   $w.t
    pack [frame     $w   -relief sunken -borderwidth 1] -fill x
    pack [text      $w.t -relief flat   -height $myX(maxS) -background [_get_color status] ] -fill x
    gui_set_readonly $cfg(objS)
    _dbx 2 "=$w }"
    return $w
}; # create_main_status_line

proc create_main_exit_button   {parent w} {
    #? create exit button
    _dbx 2 "{$parent, $w}{"
    global cfg myX
    set w   $parent.$w
    pack [frame     $w] -fill x -side bottom
    pack [button    $w.closeme  -command {exit}] -side right -padx $myX(rpad)
    _dbx 2 "=$w }"
    return $w
}; # create_main_exit_button

proc remove_main        {}  {
    #? destroy toplevel GUI, leave toplevel itself
    _dbx 2 "{}{"
    global cfg
    foreach w $cfg(guiwidgets) {
        #if {[regexp {ft_} $w]} { } # frame for host
        #dbx# puts "catch {destroy $w}"
        catch {destroy $w}
    }
    set cfg(guiwidgets) {}
    _dbx 2 "}"
    return
}; # remove_main

proc create_main  {layout}  {
    #? create toplevel GUI, layout as classic or tablet; sets $cfg(gui-layout)
    _dbx 2 "{$layout}{"
    putv  " set   layout = $layout"
    global cfg
    set cfg(gui-layout) $layout
    remove_main    ;# does not harm
    set w ""
    switch $layout {
        tablet  {
            lappend cfg(guiwidgets) [create_main_menu          $w "menu" ]
            lappend cfg(guiwidgets) [create_main_host_entries  $w ft     ]
            lappend cfg(guiwidgets) [create_main_note          $w note   ]
            pack [label $w.lm -text [_get_tipp tabMENU]]
            lappend cfg(guiwidgets) $w.lm
        }
        classic {
            lappend cfg(guiwidgets) [create_main_host_entries  $w ft     ]
            lappend cfg(guiwidgets) [create_main_quick_buttons $w fc     ]
            lappend cfg(guiwidgets) [create_main_quick_options $w fo     ]
            lappend cfg(guiwidgets) [create_main_note          $w note   ]
            lappend cfg(guiwidgets) [create_main_tabs          $w note   ]
            lappend cfg(guiwidgets) [create_main_exit_button   $w fq     ]
            guitheme_init $cfg(gui-button) ;# apply themes
        }
    }
    lappend cfg(guiwidgets) [create_main_status_line $w fl ]
    _dbx 2 "=$w }"
    return $w
}; # create_main

proc search_view  {w key}   {
    #? scroll given text widget according key
    _dbx 2 "{$w, $key}{"
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
    _dbx 2 "}"
    return
}; # search_view

proc search_show  {w mark}  {
    #? jump to mark in given text widget
    _dbx 2 "{$w, $mark}{"
    catch { $w see [$w index $mark.first] } err
    if {"" eq $err} {
        # "see" sometimes places text to far on top, so we scroll up one line
        $w yview scroll -1 units
    } else {
        _dbx 4  " err    = $err"
    }
    _dbx 2 "}"
    return
}; # search_show

proc search_mark  {w see}   {
    #? remove previous highlight, highlight at position see
    _dbx 2 "{$w, $see}{"
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
    _dbx 2 "}"
    return
}; # search_mark

proc search_more  {w search_text regex} {
    #? show overview of search results in new window
    # $w is the widget with O-Saft's help text, all matched texts are already
    # listed in $w's tag HELP-search-pos, each match is a tuple consisting of
    # start and end position (index)
    _dbx 2 "{$w, »$search_text«, $regex}{"
    global search myX
    set matches [$w tag ranges HELP-search-pos];# get all match positions
    set cnt  [_count_tuples $matches]
    set this [create_window "$cnt matches for: »$regex«" $myX(geoo)]
    set txt  [create_resulttext $this ""].t
    #{ adjust window, quick&dirty
    create_window:title   $this "[_get_text win_search_results] »$search_text«"
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
        set anf [lindex $matches $i]; incr i
        set end [lindex $matches $i]; incr i
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
        $txt tag bind   TAG-$i <ButtonPress> "$w   see $anf; search_mark $w \"$anf $end\""
        guitip_set $txt "[_get_tipp helpclick]"
        # TAG-$i  are never used again; new searches overwrite existing tags
    }
    gui_set_readonly $txt
    _dbx 2 "=$this }"
    return $this
}; # search_more

proc search_next  {w direction} {
    #? show next search text in help window
    # direction: + to search forward, - to search backward
    global search
    _dbx 2 "{$w, $direction}{"
    _dbx 4 " see    = $search(see)"
    # nextrange, prevrange return a tuple like:        23.32 23.37
    # HELP-search-pos contains something like: 2.1 2.7 23.32 23.37 42.23 42.28
    switch $direction {
      {+} { set see [$w tag nextrange HELP-search-pos [lindex $search(see) 1]] }
      {-} { set see [$w tag prevrange HELP-search-pos [lindex $search(see) 0]] }
    }
    if {"" eq $see} {
        # reached end of range, or range contains only one, switch to beginning
        set see [lrange [$w tag ranges HELP-search-pos] 0 1]   ;# get first two from list
        if {$see eq ""} { return }
        # FIXME: round robin for + but not for -
    }
    $w see [lindex $see 0]             ;# show at start of match
    search_mark $w "$see"
    #$w yview scroll 1 units           ;# somtimes necessary, but difficult to decide when
    set search(see)  $see
    _dbx 2 "}"
    return
}; # search_next

proc search_text  {w search_text} {
    #? search given text in help window's $w widget
    _dbx 2 "{$w, »$search_text«}{"
    global search
    if {[regexp ^\\s*$ $search_text]}  { return }  ;# do not search for spaces
    if {"exact" ne $search(mode)} {
        if {[string length $search_text] < 4} {
            _message warning "Search pattern" [_get_text h_min4chars]
            return
        }
    }
    if {$search_text eq $search(last)} { search_next $w {+}; return }
    # new text to be searched, initialise ...
    set search(last) $search_text
    $w tag delete HELP-search-pos      ;# tag which contains all matches
    _dbx 4 " mode           = $search(mode)"
    set regex $search_text
    set words ""       ;# will be computed below
    set rmode "-regexp";# mode (switch) for Tcl's "Text search"
    # prepare RegEx according smart and fuzzy mode; builds a new RegEx
    switch $search(mode) {
        {smart} {
            set regex [regsub -all {([(|*)])}   $regex {[\1]}] ;# some characters need to be escaped before building RegEx
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
                    set       replace {.?}
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
            # RegEx fails, when some meta characters are uses as first or last
            # character, sanitised RegEx to avoid compiling RegEx
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
    _dbx 4 " regex ($search(mode))  = $regex"
    # now handle common mistakes and set mode (switch) for Tcl's "text search"
    switch $search(mode) {
        {exact} { set rmode "-exact" }
        {smart} -
        {fuzzy} -
        {regex} {
            # simply catch compile errors using a similar call as for matching
            _dbx 4 " regex #$search(mode)#  = $regex"
            set rmode "-regexp"
            set err ""
            catch { $w search -regexp -all -nocase -- $regex 1.0 } err
            if {[regexp {compile} $err]} {
                _message warning [_get_text h_badregex] $err
                return
            }
            # else { RegEx OK }
            }
    }
    _dbx 4 " regex sanitised= $regex"
    _dbx 4 " regex mode     = $rmode"
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
        create_window:title   $warn [_get_text win_search]
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
        set e [lindex $end $i]
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
    _dbx 2 "}"
    return
}; # search_text

proc search_rset        {}  {
    #? reset/clear search list (history)
    _dbx 2 "{}{"
    global search
    set search(curr) 0
    set search(list) ""
    set search(last) ""
    set search(see)  ""
    set search(text) "";# resets entry field
    _dbx 2 "}"
    return
}; # search_rset

proc search_list  {direction} {
    #? get next or previous search text from search list (history)
    _dbx 2 "{$direction}{"
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
    _dbx 2 "}"
    return
}; # search_list

proc osaft_write_rc     {}  {
    #? print data for resource file
    # print all lines between  RC-ANF and RC-END
    _dbx 2 "{}{"
    global cfg argv0
    set qq {"} ;# dumm "
    if [catch { set fid [open $argv0 r]} err] { puts "**ERROR: $err"; exit 2 }
    # $rc_doc is used to define help text with the same syntax as used for this
    # file to avoid that it will be extracted with  --help  option, the text is
    # defined with a leading space in each line.
    # Note that the VERSION of the generated file is the same as the VERSION of
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
 #?      This file must reside in the user's  HOME  directory or the  directory
 #?      where  o-saft.tcl  will be started.
 #?
 #? SYNTAX
 #?      Content of this file must be valid Tcl syntax. Values may contain  Tcl
 #?      variables.
 #?
 #? VERSION
 #?      @(#) .o-saft.tcl generated by 3.4 24/01/26 16:50:07
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
    puts "    DESC\t{-- CONFIGURATION texts used at various places ---------------}"
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
        if {1==$skip} { continue }
        set l [regsub -all {\$0} $l $cfg(ICH)]
        puts $l
    }
    close $fid

    puts "
#-----------------------------------------------------------------------------{
#   Tcl's  option  command can be used here too, for example:
# option add *Button.font Bold
# option add *Label.font  Bold
# option add *Text.font   mono
    # NOTE  that setting other fonts may change the layout of the GUI,  it may
    #       only be necessary to adapt some sizes (see myX) too.
#
# set prg(option) 1  ;# set to 1 to avoid internal 'option add ...' commands
    # To avoid  o-saft.tcl  using its private settings,  this variable must be
    # set to  1
#-----------------------------------------------------------------------------}
";

    _dbx 2 "}"
    return
}; # osaft_write_rc

proc osaft_write_opts   {}  {
    #? extract and print options from myself
    _dbx 2 "{}{"
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
        if {![regexp {^\s*[+-]}      $l]}   { continue }
        if { [regexp {^\s*[+-]-?[*]} $l]}   { continue }
        set cols [split [regsub -all {\s+} [string trim $l] " "] " "]
        set col2 [lindex $cols 1]
        if { "\{" eq $col2 || "-" eq $col2 } { puts [lindex $cols 0] }
    }
    close $fid
    _dbx 2 "}"
    return
}; # osaft_write_opts

proc _get_data_filename  {mode} {
    _dbx 2 "{$mode}{}"
    global cfg
    return "$cfg(docs-dir)/$cfg(O-Saft).$mode" ;# TODO: directory hardcoded
}; # _get_data_filename

proc osaft_write_docs   {}  {
    #? get documentation and help texts from o-saft.pl and store in file
    # see also "make doc.data" and "make static.docs"
    _dbx 2 "{}{"
    global prg
    putv  " exec {*}$prg(PERL) $prg(SAFT) [docker_args] --no-rc --help=gen-docs"
    catch { exec {*}$prg(PERL) $prg(SAFT) [docker_args] --no-rc --help=gen-docs } txt
    _dbx 2 "}"
    return
}; # osaft_write_docs

proc osaft_read_data {norc mode} {
    #? return configuration from prg(SAFT) or corresponding file
    #  $mode denotes the type of configuration; it is also the file suffix,
    #  example: mode = "--help=data"
    #       reads:  o-saft.pl.--help=data
    #    or calls:  o-saft.pl --help=data
    _dbx 2 "{$norc,$mode}{"
    global cfg prg env
    set txt  ""
    if {"file" eq $cfg(docs-src)} {
        set file [_get_data_filename $mode]
        if {![catch {open $file  r} fid]} {
            set txt [read $fid]
            putv  " read  $file"
            close  $fid
            lappend cfg(docs-files) $file
            return $txt
        }
        _dbx 4 " error=$fid; ignored"
        if {"" ne $fid} {
            # open failed, file may not exist
            if {1==[info exists env(ANDROID_DATA)]} {
                _message warning "**WARNING: (osaft_read_data)" \
                    "no data available for »$mode« [_get_text gen_docs] "
                # AndroidWish cannot yet execute other programs :-(03/2022):-
            }
        }
    # else "dynamic"
    }
    putv  " exec {*}$prg(PERL) $prg(SAFT) [docker_args] $norc $mode"
    catch { exec {*}$prg(PERL) $prg(SAFT) [docker_args] $norc $mode } txt
    _dbx 2 "=... RC text ... }"
    return $txt
}; # osaft_read_data

proc osaft_about {mode} {
    #? extract description from myself; returns text
    _dbx 2 "{$mode}{"
    global arrv argv0
    set fid [open $argv0 r]
    set txt [read $fid]
    set hlp ""
    foreach l [split $txt "\r\n"] {
        if {![regexp {^#[?.]} $l]} { continue }
        if { [regexp {^#\.}   $l] && $mode eq {ABOUT}} { continue }
        if { [regexp {^\s*$}  $l]} { continue }
        set l [regsub -all {\$0} $l $argv0]
        set hlp "$hlp\n[regsub {^#[?.]} $l {}]"
    }
    close $fid
    _dbx 2 "=... about text ... }"
    return $hlp
}; # osaft_about

proc osaft_ciphers   {} {
    #? get description of cipher suites from o-saft.pl; returns text
    _dbx 2 "{}{"
    set help [osaft_read_data "" "--help=ciphers-text"]
    # convert to tabular data
    _dbx 2 "}"
    return $help
}; # osaft_ciphers

proc osaft_help   {}    {
    #? get help from o-saft.pl --help (for use in own help window)
    _dbx 2 "{}{"
    global cfg prg
    # get information from O-Saft; it's a performance penulty, but simple ;-)
    set help [osaft_read_data "" "--help"]
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
        set help [osaft_read_data --no-rc "--help"]
    }

    _dbx 4 " 1. collect more documentations with --help=*"
    set info ""
    foreach mode $cfg(docs-help) {
        if {{--help} eq $mode} { continue } ;# already read
        set txt ""
        set txt [osaft_read_data --no-rc $mode]
        if {2 < [llength [split $txt "\n"]]} {
            set txt [regsub -all {[&]} $txt {\\&}] ;# avoid interpretation by regexp
            set txt [regsub -all {^=   [^\n]*}  $txt {}]  ;# remove header line, the very first one
            set txt [regsub -all {\n=   [^\n]*} $txt {}]  ;# remove header lines
            set txt [regsub -all {\n=---[^\n]*} $txt {}]  ;# remove header lines
            # add section header, hardcoded (stolen from o-saft-man.pm)
            # these sections have special formatting, which will be more pretty
            # printed here:
            #   - remove empty lines
            #   - ident lines
            #   - add + prefx for commands
            set key [regsub {[-]-help=} $mode {}]  ;# simplify match
            switch $key {
              {alias}   { set head "Aliases for commands and options"
                          # expected lines like:
                          #     -t                  --starttls          # testssl.sh
                          set txt [regsub -all -line {\n}     $txt "\n        "]
                        }
              {data}    { set head "Available commands for informations"
                          # expected line like:
                          #     before - Certificate valid since
                          set txt [regsub -all -line {^\s*\n} $txt {}] ;# remove empty lines
                          set txt [regsub {^(\s*)} $txt {\1        +}] ;# pretty print first line
                          set txt [regsub -all -line {(\n)(\s*)}  $txt {\1        \2+}]
                              # each key (left) is a command, hence add +
                        }
              {checks}  { set head "Available commands for checks"
                          # expected line like:
                          #     breach - Connection is safe against BREACH attack
                          set txt [regsub {^(\s*)} $txt {\1        +}] ;# pretty print first line
                          set txt [regsub -all -line {(\n)(\s*)}  $txt {\1        \2+}]
                              # each key (left) is a command, hence add +
                        }
              {regex}   { set head "Regular expressions used internally"
                          # expected line like:
                          #     3DESorCBC3 - (?:3DES(?:[_-]EDE)[_-]CBC|DES[_-]CBC3)
                          set txt [regsub -all -line {(\n)(\s*)([^ ]+)} $txt {\1\2'\3'}]
                        }
              {rfc}     { set head "List of RFCs related to SSL, TLS" }
              {glossar} { set head "Glossar" }
              {text}    { set head "Texts used in various messages" }
              {ourstr}  { set head "Regular expressions to match our own strings" }
              {range}   { set head "List of cipherranges" }
              {compliance} { set head "INFO: Available commands for compliance checks" }
              {todo}    { set head "Known problems and bugs"              }
              default   { pwarn "unknown parameter »$mode«; ignored"; continue; }
            }
            append info "\n\nINFO $head\n$txt" ;# initial TAB for $txt important
        }
    }
    _dbx 4 " 2. merge HELP and additional help texts"
    set help [regsub "(\n\nATTRIBUTION)" $help "$info\n\nATTRIBUTION"]
    set help [regsub -all {^===.*?===} $help {}]    ;# remove informal messages

    #dbx " 3. building TOC from section head lines here is difficult, done in create_help()"

    _dbx 2 "=... help text ... }"
    return $help
}; # osaft_help

proc osaft_reset  {}    {
    #? reset all options in exe()
    _dbx 2 "{}{"
    global exe
    guistatus_set "reset"
    foreach {idx val} [array get exe] {
        if {[regexp {^[^-]} $idx]}     { continue };# want options only
        if {[string trim $val] eq "0"} { continue };# already ok
        if {[string trim $val] eq "1"} {
            set exe($idx]) 0
        } else {
            set exe($idx]) ""
        }
    }
    _dbx 2 "}"
    return
}; # osaft_reset

proc osaft_init   {}    {
    #? set values from .o-saft.pl in cfg()
    _dbx 2 "{}{"
    global cfg exe prg
    if {1==$cfg(docker)} { return };# skip in docker mode
    foreach l [split $cfg(.CFG) "\r\n"] {
        # data from .o-saft.pl, expected lines look like:
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
        _dbx 4 " exe($idx) = »$val«"
        set exe($idx) $val
    }
    # now copy commands and options from command-line to $cfg
    foreach {idx val} [array get exe] { set cfg($idx) $val }
    _dbx 2 "}"
    return
}; # osaft_init

proc _get_table   {tbl} {
    #? return all lines from the text widget (table) $tbl, except the hidden ones
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
    global cfg exe prg results
    if {"TTY" eq $type} {
        # FIXME: following type of TAB needs to be identified individually, not globally
        switch $cfg(gui-result) {
            text    { puts $results($nr)     }
            table   { puts [_get_table $tbl] }
        }
        return     ;# ready
    }
    _dbx 2 "{$tbl, $type, $nr}{"   ;# not first statement because of return before
    if {"CFG" eq $type} {
        set name [tk_getSaveFile {*}$cfg(confirm) -title "$cfg(TITLE): [_get_tipp saveconfig]" -initialfile ".$prg(SAFT)--new"]
        if {$name eq ""} { return }
        set title "Config"
        set fid  [open $name w]
        foreach {idx val} [array get cfg] { # collect selected options
            # FIXME: reading global array cfg is bad, should be array exe
            if {[regexp {^[^+-]} $idx]}    { continue };# want options and commands only
            if {[string trim $val] eq "0"} { continue };#
            if {[string trim $val] eq "1"} {
                puts $fid "$idx"
            } else {
                if {"" ne $val} { puts $fid "$idx=$val" }
            }
        }
    }
    if {$type eq "TAB"} {
        set title  [$cfg(objN) tab $nr -text];# get TAB's title
        set suffix [regsub -all {\s*\([0-9]*\)\s*} $title  {}] ;# remove (index)
        set suffix [regsub -all {[^a-zA-Z0-9_+-]}  $suffix {_}];# sanitise for filename
        set name [tk_getSaveFile {*}$cfg(confirm) -title "$cfg(TITLE): [_get_tipp saveresult]" -initialfile "$prg(SAFT)--$suffix.log"]
        if {$name eq ""} { return }
        set fid  [open $name w]
        switch $cfg(gui-result) {
            text    { puts $fid $results($nr)     }
            table   { puts $fid [_get_table $tbl] }
        }
    }
    _dbx 4 " file = $name"
    close $fid
    guistatus_set "TAB »$title« saved to $name"
    putv          " saved $name "
    _dbx 2 "}"
    return
}; # osaft_save

proc osaft_load   {cmd} {
    #? load results from file and create a new TAB for it
    #  cmd can be: _LOAD which asks for the file toload
    #              STDIN which reads data from STDIN
    #              file  which reads data from file if it exists
    _dbx 2 "{$cmd}{"
    global cfg results
    set name $cmd
    switch $cmd {
        _LOAD { set name [tk_getOpenFile -title "$cfg(TITLE): [_get_tipp loadresult]"] }
        STDIN { set fid stdin }
    }
    if {"" eq $name} { return }
    guicursor_set watch
    incr cfg(EXEC)
    if {"STDIN" ne $name} { set fid [open $name r] }
    set results($cfg(EXEC)) [read $fid]
    if {"STDIN" ne $name} { close $fid }
    set w [create_tab  $cfg(objN) $cfg(gui-result) [file tail $name] $results($cfg(EXEC))]
    apply_filter $w $cfg(gui-result) $name ;# text placed in pane, now do some markup
    # TODO: filter may fail (return Tcl error) as data is not known to be table or text
    #puts $fid $results($nr)
    guistatus_set "loaded file: $name"
    putv          " loaded $name "
    guicursor_set {}
    _dbx 2 "}"
    return
}; # osaft_load

proc osaft_exec   {parent cmd}  {
    #? run $prg(SAFT) with given command; write result to global $osaft
    # $parent is a dummy here
    _dbx 2 "{$cmd}{"
    global cfg hosts prg results
    guicursor_set watch
    guistatus_set "#{ $cmd"
    set do  {}     ;# must be set to avoid tcl error
    set opt {}     ;# ..
    set targets {} ;# ..
    if {1==$cfg(docker)} {
        # pass image ID to Docker;
        # note that this option must be before o-saft.pl commands or options
        # TODO:  docker_args() benutzen
        lappend do "-id=$prg(docker-id)"
        lappend do "-tag=$prg(docker-tag)"
    }
    if {"Start" eq $cmd} {
        foreach {idx val} [array get cfg] { # collect selected commands
            if {[regexp {^[^+]} $idx]}     { continue };# want commands only
            if {[string trim $val] ne "1"} { continue };
            lappend do $idx
        }
    } else {
        lappend do $cmd
    }
    foreach {idx val} [array get cfg] {     # collect selected options
        if {[regexp {^[^-]} $idx]}     { continue };# want options only
        set val [string trim $val]
        if {"0" eq $val} { continue }      ;# unset # FIXME: cannot use 0 as value --x=0
        if {"1" eq $val} { lappend opt  $idx; continue }
        if {""  ne $val} { lappend opt "$idx=$val"     }
    }
    foreach {i host} [array get hosts] {    # collect hosts
        if {[string trim $host] eq ""} { continue };# skip empty entries
        lappend targets  $host
    }
    # check for some special docker commands;# TODO: quick&dirty
    if {"docker_status" eq $cmd} {
        # o-saft-docker status  has no other options
        set targets {}
        set opt     {}
        set do      "-id=$prg(docker-id)"
        lappend do  "-tag=$prg(docker-tag)"
        lappend do  "status"
    }
    if {[regexp {^win(32|64)} [tk windowingsystem]]} {
        set execcmd [list exec           {*}$prg(PERL) $prg(SAFT) {*}$opt {*}$do {*}$targets]; # Tcl >= 8.5
        # Microsoft windows has no proper STDERR etc.
    } else {
        set execcmd [list exec 2>@stdout {*}$prg(PERL) $prg(SAFT) {*}$opt {*}$do {*}$targets]; # Tcl >= 8.5
        # on some systems (i.e. Mac OS X) buffering of STDOUT and STDERR is not
        # synchronised, hence we redirect STDERR to STDOUT, which is OK herein,
        # because no other process can fetch STDERR or STDOUT.
        # probaly we also need:  chan configure stdout -buffering none
    }
    # sanitise $execcmd for printing in status line and results TAB
    # Tcl uses {} to quote strings, which need to be '' for a shell
    # finally we use $execcmd for execution and $exectxt for print
    set exectxt $execcmd
    set exectxt [regsub {^\s*exec\s*.*?stdout\s*} $exectxt {}] ;# remove exec ..
    set exectxt [regsub -all {[\}\{]} $exectxt {'}]            ;# replace {}
    incr cfg(EXEC)
    set result  ""
    set status  0
    guistatus_set "$exectxt"
    putv          " $execcmd "
    if {[catch { {*}$execcmd } result errors]} {
        # exited abnormaly, get status and sanitise result
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
    set _layout $cfg(gui-result)
    if {[regexp {[+]version$} $cmd]} { set _layout "text" };# no table data (only 2 columns)
    if {"docker_status" eq $cmd}     { set _layout "text" };# don't need table here
    set txt [create_tab  $cfg(objN) $_layout $cmd $results($cfg(EXEC))]
    apply_filter $txt $_layout $cmd    ;# text placed in pane, now do some markup
    destroy $cfg(winF)                 ;# workaround, see FIXME in create_filtertab
    guistatus_set "#} $do done (status=$status)."  ;# status not yet used ...
    guicursor_set {}
    _dbx 2 "}"
    return
}; # osaft_exec

proc config_read  {}    {
    #? read configuration RC-file and IMG-file
    _dbx 2 "{}{"
    global cfg prg env
    # read $cfg(RC) if any
    # if the file does not exist, the error is silently catched and ignored
    set rcfile [file join $env(HOME) $cfg(RC)]
    if {[file isfile $rcfile]} { catch { source $rcfile } error_txt }
    set rcfile [file join {./}       $cfg(RC)]
    putv " source $rcfile"
    if {[file isfile $rcfile]} { catch { source $rcfile } error_txt }
    update_cfg                     ;# update configuration as needed
    # read $cfg(IMG)               ;# must be read before any widget is created
    read_images $cfg(gui-button)   ;# more precisely: before first use of guitheme_set
    _dbx 2 "}"
    return
}; # config_read

proc config_data  {}    {
    #? get data for commands, options and help from $prg(SAFT)
    _dbx 2 "{}{"
    global cfg prg
    # read (get) data from prg(SAFT)
    # FIXME: prg(docker-id) is missing here;  hence cfg(HELP), cfg(OPTS), cfg(CMDS)
    #        will be empty if O-Saft's default Docker image is not (found) running
    #        workaround: use environment variables, see o-saft-docker
    set norc      ""               ;# may be --no-rc if necessary
    set cfg(HELP) [osaft_help]     ;# calls also:  $prg(SAFT) +help
    set cfg(OPTS) [osaft_read_data $norc "--help=opts"]
    set cfg(CMDS) [osaft_read_data $norc "--help=commands"]
    if {5 > [llength [split $cfg(CMDS) "\n"]]} {
        # failed, so we have no commands, no options and no help text
        # checking cfg(CMDS) is sufficient, as without commands nothing can be done
        _message error "**ERROR: $prg(SAFT) failed" \
            "$prg(SAFT) did not return list of commands
----
$cfg(CMDS)
----
"
        if {0==$cfg(testtcl)} {
            exit 2
        }
    }
    _dbx 2 "}"
    return
}; # config_data

proc config_print {}    {
    #? print debug information
    _dbx 2 "{}{"
    global argv0 argv env cfg prg myX hosts

    # some platforms are picky (i.e. Android's AndroWish)-:
    global tcl_patchLevel
    global tcl_platform
    global tcl_library
    global tcl_rcFileName
    global tk_library
    global tk_patchLevel
    global tk_strictMotif

    if {"console" eq [info commands console]} { console show } ;# windows hack
    # cfg(RCSID) set in RC-file
    set rc  "not found";    if {1  == [info exists cfg(RCSID)]} { set rc  "found" }
    set ini "not found";    if {"" ne $cfg(.CFG)}               { set ini "found" }
    set tip "not used";     if {0  == $cfg(gui-tip) }           { set tip "used"  }
    set geo "";             if {1  == [info exists geometry]}   { set geo "$geometry" }
    set wmf "<<shown with --d only>>"
    set max "<<shown with --d only>>"
    set rex " |  rex*      = <<shown with --d only>>"
    set tab "<<no values>>"
    set osv $tcl_platform(osVersion)
    set sid $cfg(SID)
    set str_make "<<value not printed (OSAFT_MAKE exists)>>"
    # SEE Make:OSAFT_MAKE (in Makefile.pod)
    # TODO: string should be STR_MAKEVAL from osaft.pm
    if {1==[info exists env(OSAFT_MAKE)]} {     # avoid diff
        set osv $str_make
        set sid $str_make
    }
    if {1==$cfg(DEBUG)} {
        # use with --d only to avoid noisy output with "make test"
        set max [wm maxsize .]
        set wmf [wm frame   .] ;# returns a pointer
        if {1==[info exists env(OSAFT_MAKE)]} { # avoid diff
            set wmf $str_make
        }
    }
    if {0<[string length $cfg(objN)]} {
        set tab [$cfg(objN) tabs]
    }
    #.CFG:      $cfg(.CFG)   # don't print, too much data

    # collect important environment
    set sys "env(...)"
    foreach var [list HOME SHELL USER DISPLAY LANG PATH ANDROID_DATA OSAFT_MAKE \
                      osaft_vm_build o_saft_docker_tag o_saft_docker_name] {
        set spaces ""
        set i [string length $var]
        while {$i < 10} { append spaces " "; incr i; }
        set val ""
        if {1==[info exists env($var)]} { set val $env($var) }
        append sys "\n |  $var$spaces= $val"
    }

    # collect RegEx to match output from o-saft.pl
    if {1==$cfg(DEBUG)} {
        set rex ""
        foreach var [list rexOUT-int rexOUT-cmd rexOUT-head rexOUT-hide rexOUT-show \
                          rexCMD-int rexOPT-cfg rexOPT-help rexCOMMANDS] {
            append rex " |  $var= $prg($var)\n"
        }
        set rex [regsub \n$ $rex {}] ;# remove trailing \n
    }

    set targets ""
    foreach {i host} [array get hosts] {
        set targets "$targets $host"
    }
    set tk_wm ""
    if {1==[info exists env(ANDROID_DATA)]} {
        # some platforms are picky (i.e. Android's AndroWish)-:
        set tk_wm "'Tk  version' and 'WM  frame' not shown on Android'"
    } else {
        set tk_wm "\
|  rcFileName= $tcl_rcFileName
Tk  version   = $tk_patchLevel
 |  library   = $tk_library
 |  strictMotif= $tk_strictMotif
WM  frame     = $wmf
 |  maxsize   = $max
 |  geometry  = [wm geometry   .]
 |  focusmodel= [wm focusmodel .]
 |  system    = [tk windowingsystem]
 |  clipboard = $myX(buffer)
 |  geometry  = $geo "
    };# not Android
    set _my {}
    foreach key [lsort [array names myX]] {
        if {[regexp {^(buffer|DESC)} $key]} { continue };
        set _my "$_my\n |  $key      = $myX($key)"
    }

#dbx# puts "CFG: [array names cfg]"
#dbx# puts "EXE: [array names exe]"
#|  .CFG      = $cfg(.CFG)     ;# too many data
#|  HELP      = $cfg(HELP)     ;# too many data

    puts [regsub -all -lineanchor {^} "
ICH self      = $cfg(ICH)
 |  SID       = $sid
 |  DIR       = $cfg(DIR)
 |  ME        = $cfg(ME)
 |  IMG       = $cfg(IMG)
 |  POD       = $cfg(POD)
 |  RC        = $cfg(RC)\t$rc
 |  CDIR, pwd = $cfg(CDIR)
 |  O-Saft    = $cfg(O-Saft)
PRG $argv0
 |  INIT      = $prg(INIT)\t$ini
 |  POST      = $prg(POST)
 |  BROWSER   = $prg(BROWSER)
 |  PERL      = $prg(PERL)
 |  SAFT      = $prg(SAFT)
 |  TKPOD     = $prg(TKPOD)
 |  Ocmd      = $prg(Ocmd)
 |  Oopt      = $prg(Oopt)
 |  docker-id = $prg(docker-id)
 |  docker-tag= $prg(docker-tag)
$rex
ARG argv      = $argv
 |  targets   = $targets
 |  files     = $cfg(files)
CFG TITLE     = $cfg(TITLE)
 |  DEBUG     = $cfg(DEBUG)
 |  TRACE     = $cfg(TRACE)
 |  quit      = $cfg(quit)
 |  stdout    = $cfg(stdout)
 |  docker    = $cfg(docker)
GUI geometry $_my
GUI tooltip   = tooltip package\t$tip
 |  gui-tip   = $cfg(gui-tip)
 |  gui-button= $cfg(gui-button)
 |  gui-layout= $cfg(gui-layout)
 |  gui-result= $cfg(gui-result)
 |  docs-src  = $cfg(docs-src)
 |  docs-dir  = $cfg(docs-dir)
 |  docs-files= $cfg(docs-files)
 |  docs-help = $cfg(docs-help)
 |  guimenus  = $cfg(guimenus)
 |  guiwidgets= $cfg(guiwidgets)
 |  tabs      = $tab
 |  tab count = $cfg(EXEC)
 |  tfont     = $cfg(tfont)
 |  nbsp      = \\u[format "%02X" [scan "$cfg(nbsp)" "%c"]]
 |  buffer    = $myX(buffer)
SYS $sys
TCL version   = $tcl_patchLevel
 |  library   = $tcl_library
 |  platform  = $tcl_platform(platform)
 |  os        = $tcl_platform(os)
 |  osVersion = $osv
 |  byteOrder = $tcl_platform(byteOrder)
 |  wordSize  = $tcl_platform(wordSize)
$tk_wm
_/" "#\[$cfg(ICH)\]:"] ;# same prefix as in putv;  dumm "
    #          [tk windowingsystem] # we believe this is a window manager property
    _dbx 2 "}"
    return
}; # config_print

proc gui_init:prg {start} {
    # search browser, first matching will be used
    _dbx 2 "{}{"
    global prg
    foreach bin " $start \
            firefox chrome chromium iceweasel konqueror mozilla \
            netscape opera safari webkit htmlview www-browser w3m" {
        set binary [lindex [auto_execok $bin] 0]   ;# search in $PATH
        _dbx 4 " browser= $bin $binary"
        if {[string length   $binary]} {
            set prg(BROWSER) $binary
            break
        }
    }
    # search PODviewer, first matching will be used
    foreach bin " $start $prg(TKPOD)" {
        if {"O-Saft" eq $bin} { continue }
        set binary [lindex [auto_execok $bin] 0]   ;# search in $PATH
        _dbx 4 " viewer= $bin $binary"
        if {[string length   $binary]} {
            set prg(TKPOD)   $binary
            break
        }
    }
    _dbx 2 "}"
    return
}; # gui_init:prg

proc gui_init:cfg   {}  {
    # configure GUI according available packages
    _dbx 2 "{}{"
    global cfg IMG
    if {[catch { package require tablelist } err]} {
        pwarn "'package tablelist' not found, probably 'tklib' missing; using text layout"
        set cfg(gui-result) {text}
            # cfg(gui-result) used in create_tab() and create_filtertab()
            # it's hardcoded set to {text} here if package is missing, that's
            # working for create_filtertab() as the widgets there are created
            # only once at startup.
            # Changing cfg(gui-result) in the GUI later only affects creating
            # tables in the result tab after  osaft_exec(), and will not harm
            # widgets or functionality created by create_filtertab().
    }
    if {0==[regexp {::tk::icons::question} [image names]]} { unset IMG(help) }
        # reset if no icons there, forces text (see cfg_buttons)
    _dbx 2 "}"
    return
}; # gui_init:cfg

proc gui_init:geo   {}  {
    # configure according real size
    _dbx 2 "{}{"
    global myX
    set __x         [lindex [wm maxsize .] 0]
    set __y         [lindex [wm maxsize .] 1]
    if {$__y < $myX(miny)} { set myX(miny) $__y  }
    if {$__x < $myX(minx)} { set myX(minx) $__x  }
    if {$__x > 1000 }      { set myX(minx) "999" }
    switch [tk windowingsystem] {
        {aqua}  -
        {Aqua}  { set myX(miny)   770  ;# because fonts are bigger by default }
    }
    set myX(geoS)   "$myX(minx)x$myX(miny)"
    _dbx 2 "}"
    return
}; # gui_init:geo

proc gui_init:fonts {}  {
    # configure fonts
    _dbx 2 "{}{"
    global cfg prg
    font create osaftBold   {*}[font config TkDefaultFont] -weight bold
    font create osaftHead   {*}[font config TkFixedFont  ] -weight bold
    font create osaftSlant  {*}[font config TkFixedFont  ] -slant italic
    font create osaftBig    {*}[font config TkFixedFont]   -size 9
    if {0==$prg(option)} {  # only if not done in RC-file
        option add *Button.font osaftBold  ;# if we want buttons more exposed
        option add *Label.font  osaftBold  ;# ..
        option add *Text.font   TkFixedFont;
    }
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
    _dbx 2 "}"
    return
}; # gui_init:fonts

proc gui_init:keys_NOT_WORKING {}  {
    #? initialise key bindings, see "Key Bindings"
    _dbx 2 "{}{"
    set ignore_widgets ""
    foreach w [info commands] {
        # collect widgets, which should not get our bindings
        if {![regexp {^\.}  $w]}  { continue }
        switch [winfo class $w] {
            {Entry} -
            {Text}  { lappend ignore_widgets $w [winfo parent $w ]; continue; }
        }
    }
    foreach w [info commands] {
        if {![regexp {^\.}  $w]}  { continue }
        # exclude above bindings from entry widgets
        if {-1 < [lsearch -exact $ignore_widgets $w]} { continue }
        bind $w <Control-v>      {clipboard get    }
        bind $w <Control-c>      {clipboard clear ; clipboard append [selection get]}
        bind $w <Key-exclam>     {create_about     }
        bind $w <Key-question>   {create_help {}   }
        bind $w <Key-c>          {create_ciphers   }
        bind $w <Key-d>          {create_toolwin   }
        bind $w <Key-f>          {create_filterwin }
        bind $w <Key-g>          {create_configwin }
        bind $w <Key-h>          {create_help {}   }
        bind $w <Key-q>          {exit}
	# TODO: some bindings are not recogniced in complex widgets, like tablelist
    }
    # other tests, not working too
    #   bind .entry <Key-q> break
    #   bind .entry <Key-q> {} 
    _dbx 2 "}"
    return
}; # gui_init:keys

proc gui_init:keys  {}  {
    #? initialise key bindings, see "Key Bindings"
    _dbx 2 "{}{"
    bind . <Control-v>      {clipboard get    }
    bind . <Control-c>      {clipboard clear ; clipboard append [selection get]}
    #bind . <Key-exclam>     {create_about     }
    #bind . <Key-question>   {create_help {}   }
    #bind . <Key-c>          {create_ciphers   }
    #bind . <Key-d>          {create_toolwin   }
    #bind . <Key-f>          {create_filterwin }
    #bind . <Key-g>          {create_configwin }
    #bind . <Key-h>          {create_help {}   }
    #bind . <Key-q>          {exit}
    _dbx 2 "}"
    return
}; # gui_init:keys

proc gui_init       {}  {
    #? initialise GUI
    _dbx 2 "{}{"
    gui_init:cfg
    global cfg argv
    set __native    ""
    # next switch is ugly workaround to detect special start methods ...
    # it also does some special setup for MacOSX
    switch [tk windowingsystem] {
        {win32} { set __native "start" }
        {win64} { set __native "start" }
        {aqua}  -
        {Aqua}  { set __native "open"
                  set cfg(confirm) {}      ;# Aqua's tk_save* has no  -confirmoverwrite
                  if {[regexp -- {-(img|image)} $argv]} {
                      _message warning "(gui_init)" \
                          "using images for buttons is not recomended on Aqua systems"
                  } else {
                      set cfg(gui-button) "text";# text by default, because Aqua looks nice
                  }
                }
    }
    gui_init:prg $__native
    gui_init:fonts
    gui_init:geo
    #gui_init:keys ;# must be done very late, when all widgets are created
    _dbx 2 "}"
    return
}; # gui_init

proc gui_main       {}  {
    _dbx 2 "{}{"
    global argv0 argv env cfg prg myX hosts
    gui_init

    #| create toplevel window
    wm title        . $cfg(TITLE)
    wm iconname     . [string tolower $cfg(TITLE)]
    #wm geometry     . $myX(geoS)   ;# use only for small screens

    #| create toplevel GUI
    set w [create_main $cfg(gui-layout)]

    osaft_init     ;# initialise options from .-osaft.pl (values shown in Options tab)

    #| load files, if any
    foreach f $cfg(files) {
        if {"STDIN"!=$f && ![file exists $f]} { continue }
        osaft_load $f
    }

    #| special test output
    if {0<$cfg(stdout)} {
        $cfg(objT) invoke  ;# call button to save on STDOUT
    }

    #| some verbose output
    putv " hosts=[array size hosts]"
    set vm ""      ;# check if inside docker
    if {1==[info exist env(osaft_vm_build)]} { set vm "($env(osaft_vm_build))" }
    if {1==$cfg(docker)}                     { set vm "(using $prg(SAFT))" }
    guistatus_set "$argv0 $vm $argv"
        # full path and all passed arguments; useful if started from .desktop file
    if {0 < ($cfg(VERB) + $cfg(DEBUG))} { config_print }
        # must be at end when window was created, otherwise wm data is missing or mis-leading

    #| GUI ready, initialise tracing if required
    if {0 < $cfg(TRACE)} { trace_buttons }

    gui_init:keys

    _dbx 2 "}"
    return
}; # gui_main

#_____________________________________________________________________________
#_____________________________________________________________________ main __|

set doit    0
# see ADDITIONAL SYNOPSIS above
switch $cfg(ICH) {
    osaft--testtcl.tcl  -
    o-saft--testtcl.tcl { set cfg(DEBUG)    97; set cfg(quit) 1; set cfg(testtcl) 1 }
    osaft--test-docs    -
    o-saft--test-docs   { set cfg(DEBUG)    98; }
    osaft--d.tcl        -
    o-saft--d.tcl       { set cfg(DEBUG)    1;  }
    osaft--trace.tcl    -
    o-saft--trace.tcl   { set cfg(TRACE)    1;  }
};# switch cfg(ICH)
#| main: arguments and options
#  for some options following variants are allowed: {^--?(PREFIX-?)?OPT=}
#  which is:   -OPT=val  -PREFIXOPT=val  -PREFIX-OPT=val
#             --OPT=val --PREFIXOPT=val --PREFIX-OPT=val
foreach arg $argv {
    switch -glob $arg {
        +VERSION        { puts $cfg(VERSION);        exit;      }
        --version       { puts $cfg(mySID);          exit;      }
        --h             -
        --help          { puts [osaft_about "HELP"]; exit;      }
        --help=opts     { osaft_write_opts;          exit;      }
        --rc            { osaft_write_rc;            exit;      }
        --gen-docs      { osaft_write_docs;          exit;      }
        --nodoc         -
        --nodocs        -
        --no-docs       { set   cfg(docs-src) "dynamic";        }
        --post=*        { set   prg(POST)   $arg;               }
        --pod*          { set   prg(TKPOD)  "podviewer";        }
        --tkpod         { set   prg(TKPOD)  "tkpod";            }
        --load=*        { lappend cfg(files)    [regsub {^--load=} $arg {}]; }
        --stdin         { lappend cfg(files)    "STDIN";        }

        options__for_runtime_behavior { set dumm "-----------"; }
        options__for_use_with_docker  { set dumm "-----------"; }
         -docker        -
        --docker        { config_docker opt;                    }
         -id=*          -
         -dockerid=*    -
         -docker-id=*   -
        --id=*          -
        --dockerid=*    -
        --docker-id=*   { set   prg(docker-id)  [regsub {^--?(docker-?)?id=}  $arg {}]; }
         -tag=*         -
         -dockertag=*   -
         -docker-tag=*  -
        --tag=*         -
        --dockertag=*   -
        --docker-tag=*  { set   prg(docker-id)  [regsub {^--?(docker-?)?tag=} $arg {}]; }

        options__for_GUI_behaviour    { set dumm "-----------"; }
        --gui                { }
        --tip                -
        --gui-tip            { set  cfg(gui-tip)     1;         }
        --img                -
        --image              -
        --gui-button=image   { set  cfg(gui-button)  "image";   }
        --text               -
        --gui-button=text    { set  cfg(gui-button)  "text";    }
        --gui-result=text    { set  cfg(gui-result)  "text" ;   }
        --gui-result=table   { set  cfg(gui-result)  "table";   }
        --gui-layout=note    -
        --gui-layout=classic { set  cfg(gui-layout)  "classic"; }
        --gui-layout=tablet  { set  cfg(gui-layout)  "tablet" ; }
        --gui-layout=window  { set  cfg(gui-layout)  "window";  }

        options__for_debugging__only  { set dumm "-----------"; }
        --dbx                -
        --d                  { set  cfg(DEBUG)  1;              }
        --d=*                { set  cfg(DEBUG)  [regsub {^--d=} $arg {}]; }
        --trace              { set  cfg(TRACE)  1;              }
        --v                  { set  cfg(VERB)   1;              }

        options__for_testing__only    { set dumm "-----------"; }
        +quit                { set  cfg(quit)   1;              }
        --test=*         { lappend  cfg(files)  [regsub {^--test=} $arg {}];
                               set  cfg(stdout) 1;
                               set  cfg(quit)   1;
                             }
        --test-tcl           -
        --testtcl            { set  cfg(DEBUG)  97; set cfg(quit) 1; set cfg(testtcl) 1; }
        --test-docs          { set  cfg(DEBUG)  98;             }
        --test-o-saft        -
        --test-osaft         -
        --testosaft          { set  cfg(DEBUG)  99;             }

        options__passed_to_o-saft     { set dumm "-----------"; }
        --*                  { set  exe($arg)   1;              }
        +*                   { set  exe($arg)   1; set doit 1;  }
        *                    { set  hosts([array size hosts]) $arg; }
        default              { pwarn "unknown parameter »$arg«; ignored" }
    }
}
if {0<$cfg(DEBUG)}  { set cfg(VERB) 1; set myX(maxS) 10; }
if {0<$cfg(TRACE)}  { trace_commands;  }
if {0<$cfg(VERB)}   { lappend prg(Ocmd) {+quit} {+version}; }
if {0<$cfg(docker)} { lappend prg(Ocmd) {docker_status};    }
if {98==$cfg(DEBUG)} { foreach mode $cfg(docs-help-all) { puts [_get_data_filename $mode]; }; exit; }

#| read $cfg(RC) and $cfg(IMG), data from $prg(SAFT)
config_read
config_data

#| special debug output
if {99==$cfg(DEBUG)} { puts "$cfg(HELP)"; exit; }
if {97==$cfg(DEBUG)} {
    config_print
    if {0<$cfg(testtcl)} {
        _message info "$cfg(ICH) --test-tcl" "click \[OK\] to exit"
    }
    exit
}

gui_main

#| start main (event loop)
if {1==$doit}      { osaft_exec . "Start" };# call o-saft.pl if commands are given
if {1==$cfg(quit)} { putv " exit"; exit }  ;# special for testing with Makefile*

