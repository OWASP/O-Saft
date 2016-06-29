#!/usr/bin/tclsh
#?
#? NAME
#?      .o-saft.tcl -  resource file for o-saft.tcl
#?
#? SYNOPSIS
#?      source .o-saft.tcl
#?
#? DESCRIPTION
#?      This is the user-configuration file for O-Saft's GUI  o-saft.tcl.
#?
#? USAGE
#?      This file is in O-Saft's  contrib  directory and must be copied to the
#?      user's  HOME  directory or the local directory where o-saft.pl will be
#?      started.
#?
#? SYNTAX
#?      Content of this file must be valid Tcl syntax.
#?
#? VERSION
#?      @(#) .o-saft.tcl 1.3 16/06/29 09:11:12
#?
#? AUTHOR
#?      04. April 2016 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

package require Tcl 8.5

set cfg(TITLE)  {O-Saft}

#_____________________________________________________________________________
#_____________________________________________________ settings for colours __|

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

#_____________________________________________________________________________
#_____________________________________________ texts for labels and buttons __|

array set cfg_label {
    DESC        {CONFIGURATION texts used in GUI for buttons or labels}
    about       {About}
    close       {Close}
    closetab    {Close TAB}
    color       {Color Chooser}
    font        {Font Chooser}
    filter      {Filter}
    minus       {-}
    plus        {+}
    quest       {?}
    quit        {Exit}
    reset       {Reset}
    start       {Start}
    save        {Save}
    host        {Host[:Port]}
    hideline    {Hide complete line}
    c_toggle    "toggle visibility\nof various texts"
}

#_____________________________________________________________________________
#_______________________________________________________ texts for tooltips __|

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
    choosen     {Choosen value}
    start       "Start $cfg(SAFT) with command "
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
    f_key       {Key}
    f_moder     {r}
    f_modee     {e}
    f_chars     {#}
    f_regex     {Regex}
    f_fg        {Foreground}
    f_bg        {Background}
    f_font      {Font}
    f_u         {u}
}

# Note: Text for tab* contain new lines.

#_____________________________________________________________________________
#_______________________________________________________ settings for sizes __|

set myX(DESC)   {CONFIGURATION window manager geometry}
#   set minimal window sizes to be usable in a 1024x768 screen
#   windows will be larger if the screen supports it (we rely on "wm maxsize")
set myX(geoO)   "600x720-0+0";  # geometry and position of Help    window
set myX(geo-)   "";             # 
#set myX(geoS)  "700x720";      # geometry and position of O-Saft  window
set myX(geoA)   "600x610";      # geometry and position of About   window
set myX(geoF)   "";             # geometry and position of Filter  window (computed dynamically)
set myX(geoT)   "";             # 
set myX(minx)   700;            # O-Saft  window min. width
set myX(miny)   720;            # O-Saft  window min. height
set myX(lenl)   15;             # fixed width of labels in Options window
set myX(rpad)   15;             # right padding in the lower right corner
set myX(padx)   5;              # padding to right border

#_____________________________________________________________________________
#____________________________________________________________ misc settings __|

#----------------------------------------------------- where to find o-saft.pl
    # if o-saft.pl will not be found with the system's PATH environment
    # variable, a full path to o-saft.pl can be set here

set cfg(SAFT)   {o-saft.pl};    # name of O-Saft executable

#--------------------------------- list of buttons for "quick access commands"
    # for each O-Saft command in this list a button will be created in
    # the GUI 
    # NOTE that this must be commands for o-saft.pl, which usually start
    # with  +  character

set cfg(FAST)   {{+check} {+cipher} {+info} {+quick} {+protocols} {+vulns}};

#------------------------------------------------------ executable for browser
    # o-saft.tcl tries to find the browser automatically, it uses a list 
    # of well known browser names for that. If another browser should be
    # used, it can be set here.
    # Must be a full path or found with PATH environment variable.

set cfg(browser) "";

#-------------------------------------------- set font for various tcl widgets
    # NOTE that setting other fonts may change the layout of the GUI, it
    # may be necessary to adapt some sizes (see myX) too.

# option add *Button.font Bold;
# option add *Label.font  Bold;
# option add *Text.font   mono;

