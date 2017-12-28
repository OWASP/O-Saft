#!/usr/bin/tclsh
#?
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
#?      This file is in O-Saft's  contrib  directory and must be copied to the
#?      user's  HOME directory or the local directory where o-saft.tcl will be
#?      started.
#?
#? SYNTAX
#?      Content of this file must be valid Tcl syntax.
#?
#? VERSION
#?      @(#) .o-saft.tcl 1.14 17/12/28 23:35:20
#?
#? AUTHOR
#?      04. April 2016 Achim Hoffmann
#?
# -----------------------------------------------------------------------------
set cfg(RCSID)  {1.14};  # initial SID, do not remove

package require Tcl 8.5

set cfg(TITLE)  {O-Saft}

#_____________________________________________________________________________
#_____________________________________________________ settings for colours __|

array set cfg_color "
    DESC        {-- CONFIGURATION colours used for buttons -------------------}
    closeme     orange
    closetab    orange
    closewin    orange
    cmdstart    yellow
    cmdcheck    #ffd800
    cmdcipher   #ffd000
    saveresult  lightgreen
    saveconfig  lightgreen
    reset       lightblue
    filter      lightblue
    DESC_other  {-- CONFIGURATION colours used for other objects -------------}
    osaft       gold
    button      lightyellow
    code        lightgray
    link        blue
    status      wheat
";

#_____________________________________________________________________________
#_____________________________________________ texts for labels and buttons __|

array set cfg_label "
    DESC        {-- CONFIGURATION texts used in GUI for buttons --------------}
    about       {!}
    help        {?}
    closeme     {Quit}
    closewin    {Close}
    closetab    {Close TAB}
    saveresult  {Save}
    saveconfig  {Save}
    reset       {Reset}
    filter      {Filter}
    tkcolor     {Color Chooser}
    tkfont      {Font Chooser}
    host_del    {-}
    host_add    {+}
    help_home   {^}
    help_prev   {<}
    help_next   {>}
    helpsearch  {>>}
    cmdstart    {Start}
    cmdcheck    {+check}
    cmdcipher   {+cipher}
    cmdinfo     {+info}
    cmdquick    {+quick}
    cmdquit     {+quit}
    cmdprotocols {+protocols}
    cmdvulns    {+vulns}
    cmdversion  {+version}
    DESC_other  {-- CONFIGURATION texts used in GUI for labels ---------------}
    host        {Host\[:Port\]}
    hideline    {Hide complete line}
    c_toggle    {toggle visibility\nof various texts}
";

#_____________________________________________________________________________
#_______________________________________________________ texts for tooltips __|

array set cfg_tipp "
    DESC        {-- CONFIGURATION texts used for tool tips on buttons --------}
    help        {Open window with complete help}
    closeme     {Close program}
    closetab    {Close this TAB}
    closewin    {Close window}
    saveresult  {Save result to file}
    saveconfig  {Save configuration to file}
    showfilterconfig {Show configuration for filtering results}
    resetfilterconfig {Reset configuration to values from $cfg(INIT)}
    settings    {Open window with more settings}
    host_del    {Remove this line for a host}
    host_add    {Add new line for a host}
    tkcolor     {Open window to choose a color}
    tkfont      {Open window to choose a font}
    help_home   {Go to top of page (start next search from there)}
    help_prev   {Search baskward for text}
    help_next   {Search forward for text}
    helpsearch  {Text to be searched}
    cmdstart    {Execute $cfg(SAFT) with commands selected in 'Commands' tabs }
    cmdcheck    {Execute $cfg(SAFT) +check}
    cmdcipher   {Execute $cfg(SAFT) +cipher}
    DESC_other  {-- CONFIGURATION texts used for tool tips on other objects --}
    choosen     {Choosen value}
    hideline    {Hide complete line instead of pattern only}
    show_hide   {show/hide: }
    help_mode   {Mode how pattern is used for searching}
    helpclick   {Click to show in Help window}
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
    DESC_misc   {-- CONFIGURATION texts used in GUI for various texts --------}
    f_key       {Key}
    f_moder     {r}
    f_modee     {e}
    f_chars     {#}
    f_regex     {Regex}
    f_fg        {Foreground}
    f_bg        {Background}
    f_font      {Font}
    f_u         {u}
    DESC_opts   {-- CONFIGURATION texts used in GUI for option checkbuttons --}
    --header    {print header line}
    --enabled   {print only enabled ciphers}
    --no-dns    {do not make DNS lookups}
    --no-http   {do not make HTTP requests}
    --no-sni    {do not make connections in SNI mode}
    --no-sslv2  {do not check for SSLv2 ciphers}
    --no-tlsv13 {do not check for TLSv13 ciphers}
";

# Note: Text for tab* contain new lines.

#_____________________________________________________________________________
#_______________________________________________________ settings for sizes __|

#----------------------------------------------------- window manager geometry
    # set minimal window sizes to be usable in a 1024x768 screen
    # windows will be larger if the screen supports it (we rely on "wm maxsize")

set myX(geoO)   "600x720-0+0";  # geometry and position of Help    window
set myX(geo-)   "";             # (reserved for future use)
#et myX(geoS)  "700x720";       # geometry and position of O-Saft  window
set myX(geoA)   "600x610";      # geometry and position of About   window
set myX(geoF)   "";             # geometry and position of Filter  window (computed dynamically)
set myX(geoT)   "";             #
set myX(minx)   700;            # O-Saft  window min. width
set myX(miny)   720;            # O-Saft  window min. height

#---------------------------------------------------- some special GUI objects
set myX(lenl)   15;             # fixed width of labels in Options window
set myX(rpad)   15;             # right padding in the lower right corner
set myX(padx)   5;              # padding to right border

#_____________________________________________________________________________
#____________________________________________________________ misc settings __|

#----------------------------------------------------- where to find o-saft.pl
    # if o-saft.pl will not be found with the system's PATH environment
    # variable, a full path to o-saft.pl can be set here

set prg(SAFT)   {o-saft.pl};    # name of O-Saft executable

#--------------------------------------------------- viewer to show o-saft.pod
    # o-saft.tcl uses built-in functionality to show its  documentation.  This
    # documentation is available in POD format also: o-saft.pod.
    # If this variable is set to the name of an external program, this program
    # will be used to show the documentation.  It is recommended to use full a
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
    #    *          - all viewers must be started in background and will not be
    #                 closed with o-saft.tcl itself

set prg(TKPOD)  {O-Saft};       # name of executable to view O-Saft's POD file

#--------------------------------- list of buttons for "quick access commands"
    # for each O-Saft command in this list a button will be created in
    # the GUI
    # NOTE that this must be commands for o-saft.pl, which usually start
    # with  +  character

set prg(Ocmd)   {{+check} {+cipher} {+info} {+quick} {+protocols} {+vulns}};

#------------------------------- list of checkboxes for "quick access options"

set prg(Oopt)   {{--header} {--enabled} {--no-dns} {--no-http} {--no-sni} {--no-sslv2} {--no-tlsv13}};


#------------------------------------------------------ executable for browser
    # o-saft.tcl tries to find the browser automatically, it uses a list
    # of well known browser names for that. If another browser should be
    # used, it can be set here.
    # Must be a full path or found with PATH environment variable.

# set prg(BROWSER) "";

#----------------------------------------- buttons style: simple text or image
set cfg(bstyle) {image};        # button style: {image} or {text}
set cfg(layout) {text};         # layout o-saft.pl's results:  text  or  table

#-------------------------------------------- set font for various tcl widgets
    # NOTE that setting other fonts may change the layout of the GUI, it
    # may be necessary to adapt some sizes (see myX) too.

# option add *Button.font Bold;
# option add *Label.font  Bold;
# option add *Text.font   mono;

#------------------------------------- when to show overview of search results
set search(more) 5;         # show overview when more than this search results

