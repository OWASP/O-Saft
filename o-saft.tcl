#!/usr/bin/wish
##  # restarts using wish \
##  exec wish8.6 "$0" ${1+"$@"}

#?
#? NAME
#?      $0 - simple GUI for o-saft.pl
#?
#? DESCRIPTION
#?      This is a simple GUI for  O-Saft - OWASP SSL advanced forensic tool.
#?      The GUI supports all commands and options available in  o-saft.pl.
#?      It executes  o-saft.pl  as specified, and prints results in a new  TAB
#?      of the GUI. Results and settings (commands and options) can be saved.
#?
#? SYNOPSIS
#?      $0 [host:port] [host:port] ...
#?
#? ARGUMENTS
#?      All arguments, except --help, are treated as a hostname to be checked.
#?
#? LIMITATIONS
#?      All filenames (for Save) are hardcoded and will be overwritten.
#?
#. LAYOUT
#.           +---------------------------------------------------------------+
#.       (H) | Host:Port [________________________________________]  [+] [-] |
#.           |                                                               |
#.       (C) | [Start] [+info] [+check] [+cipher] [+quick] [+vulns]      [?] |
#.           |---------------------------------------------------------------|
#.           | +---------++----------++----------++----------+               |
#.       (T) | | Options || Commands || (n) +cmd || (m) +cmd |               |
#.           | +         +-------------------------------------------------+ |
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
#.       (T) - Frame containing panes for commands options, and results
#.       (S) - Frame containing Status messages
#.
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
#.      commands and options may be missing iin the generated GUI.
#.      Following options are used:  --help=toc  --help=opt  --help=commands
#.
#. HACKER's INFO
#.      The tool will only work if o-saft.pl is available and executes without
#.      errors. All commands and options of  o-saft.pl  will be available from
#.      herein, except:
#.          - all "--help*" options (as they make no sense here)
#.          - "+cgi" and "+exec" command (they are for internal use only)
#.
#.     This is no academically perfect code, but quick&dirty scripted:
#.       - makes use of global variables instead of passing parameters etc..
#.       - mixes layout and functions and business logic
#.       - some widget names are hardcoded
#.
#? VERSION
#?      @(#) 1.1 Easterhack 2015
#?
#? AUTHOR
#?      04. April 2015 Achim Hoffmann (at) sicsec de
#?
# -----------------------------------------------------------------------------

package require Tcl     8.5
package require Tk      8.5

set cfg(SID)    {@(#) o-saft.tcl 1.1 15/04/07 09:09:08 Easterhack 2015}
set cfg(TITLE)  {O-Saft}

set cfg(TIP)    [catch { package require tooltip} tip_msg];  # 0 on success, 1 otherwise!

#-----------------------------------------------------------------------------{
#   CONFIGURATION
#   this is the only section where we know about o-saft.pl
#   all settings for o-saft.pl go here
set cfg(SAFT)   {o-saft.pl}
set cfg(INIT)   {.o-saft.pl}
set cfg(.CFG)   {}
catch {
  set fid [open $cfg(INIT) r]
  set cfg(.CFG) [read $fid];   close $fid;          # read .o-saft.pl
}
set toc      "\nCONTENT\n[exec $cfg(SAFT) +help=toc]"
set cfg(HELP)   "$toc\n\n[exec $cfg(SAFT) +help]";  # get all texts at startup
set cfg(OPTS)   [exec $cfg(SAFT) --help=opt];       # which is a performance
set cfg(CMDS)   [exec $cfg(SAFT) --help=commands];  # penulty :-(
set cfg(FAST)   {{+check} {+cipher} {+info} {+quick} {+vulns}}; # quick access commands
#-----------------------------------------------------------------------------}

#   internal data storage
set cfg(CDIR)   [file join [pwd] [file dirname [info script]]]
set cfg(INFO)   ""; # text to be used in status line
set cfg(EXEC)   0;  # count executions, used for object names
set cfg(x--x)   0;  # each option  will have its own entry (this is a dummy)
set cfg(x++x)   0;  # each command will have its own entry (this is a dummy)
set cfg(NOTE)   ""; # object name of notebook; needed to add more note TABS
set cfg(ABOUT)  ""; # object name of About window
set cfg(POSY)   [winfo y .]; # used to position other windows
set cfg(POSX)   [winfo x .]; incr cfg(POSX) 100;
set cfg(VERB)   0;  # set to 1 to print more informational messages from Tcl/Tk
set hosts(0)    0;  # array containing host:port; index 0 contains counter
set tab(0)      ""; # contains results of cfg(SAFT)

proc str2obj {str} {
    #? convert string to valid Tcl object name; returns new string
    set name [regsub -all {[+]} $str  {Y}];     # commands
    set name [regsub -all {[-]} $name {Z}];     # options (mainly)
    set name [regsub -all {[^a-zA-Z0-9_]} $name {X}];
    set name "o$name";  # first character must be lower case letter
    return $name
}; # str2obj

proc show_window {w} {
    #? show window near current cursor position
    set y   [winfo pointery $w]; incr y 23
    set x   [winfo pointerx $w]; incr x 23
    wm geometry  $w "+$x+$y"
    wm deiconify $w
}; # show_window

proc create_window {title size} {
    #? create new toplevel window with given title and size; returns widget
    set this    .[str2obj $title]
    toplevel    $this
    wm title    $this "O-Saft: $title"
    wm iconname $this "o-saft: $title"
    wm geometry $this $size
    pack [frame $this.f0  -relief sunken -borderwidth 1] -fill x -side top
    pack [label $this.f0.l  -text $title -font TkCaptionFont]    -side left
    pack [frame $this.f1  -relief sunken -borderwidth 1] -fill x -side bottom
    pack [button $this.f1.q -text Dismiss -bg orange -command "wm iconify $this"] -side right
    create_tip   $this.f1.q "Close Window"
    if {$title ne "Help"} {
        # all other windows have Save button
        pack [button $this.f1.s -text Save -bg lightgreen -command {osaft_save "CFG" 0}] -side left
        create_tip   $this.f1.q "Save configuration to file"
    };
    return $this
}; # create_window

proc create_tip {parent txt} {
    #? add tooltip message to given widget
    global cfg
    if {$cfg(TIP) == 1} { return }; # package not available
    tooltip::tooltip $parent $txt
}; # create_tip

proc create_host {parent} {
    #?  frame with label and entry for host:port; $nr is index to hosts()
    global cfg hosts
    incr hosts(0)
    if {$cfg(VERB)==1} { puts "create host $hosts(0)" }
    set this $parent.ft$hosts(0)
          frame  $this
    pack [label  $this.lh -text {Host[:Port]}]                         -side left
    pack [entry  $this.eh -textvariable hosts($hosts(0))]              -side left -fill x -expand 1
    pack [button $this.bp -text {+} -command "create_host {$parent};"] -side left
    pack [button $this.bm -text {-} -command "remove_host $this; set hosts($hosts(0)) {}"] -side left
    create_tip   $this.bm "Remove this line for a host"
    create_tip   $this.bp "Add new line for a host"
    if {$hosts(0) == 1} {
        # do not remove the first one; instead change the {-} button to {about}
        $this.bm configure -text {!} -command "show_window $cfg(ABOUT)"
        create_tip $this.bm "About $cfg(TITLE)"
    }
    set prev $parent.ft[expr $hosts(0) - 1]
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
    $this.t insert end $txt
    $this.t config -state disabled
    pack $this.s -side right -fill y  -pady 2 -padx {0 2} -in $this
    pack $this.t -fill both -expand 1 -pady 2 -padx {2 0} -in $this
    return $this
}; # create_text

proc create_help {} {
    #? create new window with complete help; returns widget
    global cfg
    set this    [create_window {Help} "600x800-0+0"]
    set help    [regsub -all {===.*?===} $cfg(HELP) {}];  # remove informal messages
    set txt     [create_text $this $help].t
    # mark all headlines blue
    foreach idx [$txt search -all -regexp {^ *([A-Z_ -]+)$} 2.1] {
        #set name [str2obj $match]
        $txt tag add  osaft-TOC  $idx "$idx + 1 line - 1 char"
    }
    # FIXME: bindings miss proper tags
    ## set binding for headline from TOC
    #foreach idx [$txt search -all -regexp {^([A-Z_ -]+)$} 2.1] {
    #    $txt tag bind osaft-TOC  <ButtonPress> "$txt see $idx"
    #}

    $txt tag config  osaft-TOC  -foreground BLUE -underline 1
    wm iconify  $this
    return $this
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
}; # remove_note

proc create_cmd {parent title color} {
    #? create button to run O-Saft command; returns widget
    global cfg
    set name [str2obj $title]
    set this $parent.$name
    if {$color < 1 || $color > 4} { set color ""}
    pack [button $this -text $title -bg "gold$color" -command "osaft_exec $parent $title"] -side left
    create_tip   $this "Execute $cfg(SAFT) with command $title"
    return $this
}; # create_cmd

proc create_opts {parent cmd} {
    #? create checkbox buttons; can be used for commands and options
    #  creates one button for each line returned by: o-saft.pl --help=opt|commands
    # cmd must be "OPT" or "CMD" or "TRC"
    global cfg
    set this $parent
    set grp  $this
    set data $cfg(OPTS)
    if {$cmd eq "CMD"} { set data $cfg(CMDS) }
    set max  0; # FIXME: quick&dirty fix to avoid huge windows
    set cnt  0; # FIXME: ..
    set txt  "";# FIXME: ..
    foreach l [split $data "\r\n"] {
        set dat [string trim $l]
        if {$dat eq ""}                      { continue; }
        ### skipped commands
        if {[regexp {^\+(cgi|exec)} $dat]} { continue; }; # internal use only
        ### skipped options
        if {$dat eq "OPTIONS"} { continue; }
        if {[regexp {^--h$}         $dat]} { continue; }
        if {[regexp {^--help}       $dat]} { continue; }
        if {[regexp {^--(cgi|call)} $dat]} { continue; }; # use other tools for that
        if {[regexp {^[^+-]} $dat] || $max > 36} {
            if {$max > 36} { incr cnt; set dat $txt }
            set max  0
            set hoch 500
            set name [str2obj $dat]$cnt
            incr cfg(POSX) 25;
            incr cfg(POSY) 25;
            if {[regexp {(checked|SSL) connection} $dat]} { set hoch 750 }; # <<== dirty hack ;-(
            set grp  [create_window "$dat $cnt" "300x$hoch+$cfg(POSX)+$cfg(POSY)"]
            wm iconify $grp
            pack [button $this.$name -text $dat -command "show_window $grp"] \
                 -anchor w -fill x -padx 10 -pady 2
            create_tip   $this.$name "Open window with more settings"
            set txt $dat;     # save current button text
            continue
        }
        incr max
        set dat [lindex [split $dat " \t"] 0]
        if {$cfg(VERB)==1} { puts ">$dat<" }
        set name [str2obj $dat]
        if {[winfo exists $grp.$name]} {
            if {$cfg(VERB)==1} {puts "existing: $grp.$name"};
            continue
        }
        if {[regexp {=} $l]} {
            regexp {^([^=]*)=(.*)} $l dumm idx val
            frame $grp.$name
            pack [label  $grp.$name.l -text $idx]              -side left
            pack [entry  $grp.$name.e -textvariable cfg($idx)] -side left -fill x -expand 1
            pack $grp.$name -fill x -anchor w
            if {[regexp {^[a-z]*$} $l]} { set cfg($idx) $val };   # only set if all lower case
        } else {
            pack [ttk::checkbutton $grp.$name -text $dat -variable cfg($dat)] -anchor w
            # use ttk::checkbutton 'cause checkbutton alway aligns centered
        }
    }
}; # create_opts

proc osaft_about {mode} {
    #? extract description from myself; returns text
    global arrv argv0
    set fid [open $argv0 r]
    set txt [read $fid]
    set hlp ""
    foreach l [split $txt "\r\n"] {
        if {![regexp {^#[?.]} $l]} { continue; }
        if {[regexp {^#\.}  $l] && $mode eq {ABOUT}} { continue }
        if {[regexp "^\s*$" $l]} { continue }
        set l [regsub -all {\$0} $l $argv0]
        set hlp "$hlp\n[regsub {^#[?.]} $l {}]"
    }
    close $fid
    return $hlp
}; # osaft_about

proc osaft_reset {} {
    #? reset all options in cfg()
    global cfg
    set cfg(INFO) "reset"; update idletasks;
    foreach {idx val} [array get cfg] {
        if {[regexp {^[^-]} $idx]}     { continue };# want options only
        if {[string trim $val] eq "0"} { continue };# already ok
        if {[string trim $val] eq "1"} {
            set cfg($idx]) 0
        } else {
            set cfg($idx]) ""
        }
    }
    update idletasks
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
    update idletasks
}; # osaft_init

proc osaft_save {type nr} {
    #? save selected output to file; $nr used if $type == TAB
    # type denotes type of data (TAB = tab() or CFG = cfg()); nr denotes entry
    global cfg tab
    if {$type eq "TAB"} {
        set name "$cfg(SAFT)--$nr.log"
        set fid  [open $name w]
        puts $fid $tab($nr)
    }
    if {$type eq "CFG"} {
        set name ".$cfg(SAFT)--new"
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
    set cfg(INFO) "saved to $name"; update idletasks;# enforce display update
}; # osaft_save

proc osaft_exec {parent cmd} {
    #? run $cfg(SAFT) with given command; write result to global $osaft
    global cfg hosts tab
    set cfg(INFO) "$cmd"; update idletasks;         # enforce display update
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
        if {$i == 0}                { continue };   # first entry is counter
        if {[string trim $h] eq ""} { continue };   # skip empty entries
        lappend targets $h
    }
    set execme [list exec $cfg(SAFT) {*}$opt {*}$do {*}$targets]; # Tcl >= 8.5
    set cfg(INFO) "$execme"; update idletasks;      # enforce display update
    incr cfg(EXEC)
    catch {
       #set osaft [eval $execme]; # Tcl < 8.5
        set osaft [{*}$execme];   # Tcl > 8.4
    } exec_msg
    set execme [regsub "^\s*exec\s*" $execme {}];   # pretty print command
    set tab($cfg(EXEC)) "\n$execme\n\n$exec_msg\n"
    set tab_run  [create_note $cfg(NOTE) "($cfg(EXEC)) $cmd"]
    set txt [create_text  $tab_run $tab($cfg(EXEC))].t ;    # <== ugly hardcoded .t
    pack [button $tab_run.bs -text {Save}  -bg lightgreen -command "osaft_save {TAB} $cfg(EXEC)"] -side left
    pack [button $tab_run.bq -text {Close TAB} -bg orange -command "destroy $tab_run"] -side right
    create_tip   $tab_run.bq "Close window"
    create_tip   $tab_run.bs "Save result to file"
    # text placed in pane, now do some markup
    # FIXME: the indices  wordend and lineend do not work :-(
    #        hence some cumbersome indicies used below
    foreach idx [$txt search -all -regexp "$cfg(SAFT).*\n\n" 2.1] {
        # o-saft command is preceded and followed by empty line
        $txt tag add osaft-CMD  "$idx - 1 line" "$idx + 2 line - 1 char"
    }
    foreach idx [$txt search -all -regexp "yes\n" 2.1] {
        $txt tag add osaft-YES  $idx "$idx + 3 char"
    }
    foreach idx [$txt search -all -exact  "no (" 2.1] {
        $txt tag add osaft-NO   $idx "$idx + 3 char"
    }
    foreach idx [$txt search -all -exact  "HIGH" 2.1] {
        $txt tag add osaft-HIGH $idx "$idx + 4 char"
    }
    foreach idx [$txt search -all -regexp -nocase "(LOW|WEAK)" 2.1] {
        $txt tag add osaft-WEAK $idx "$idx + 4 char"
    }
    foreach idx [$txt search -all -exact  "**WARN" 2.1] {
        $txt tag add osaft-WARN $idx "$idx + 1 line - 1 char"
    }
    foreach idx [$txt search -all -regexp {^==*} 2.1] {
        $txt tag add osaft-CMT  $idx "$idx + 1 line - 1 char"
    }
    foreach idx [$txt search -all -regexp {^#[^[]} 2.1] {
        # note: regex does not match #[ which is used with --trace-key
        $txt tag add osaft-DBX  $idx "$idx + 1 line - 1 char"
    }
    $txt tag config  osaft-CMD  -background black -foreground white
    $txt tag config  osaft-YES  -background lightgreen;;
    $txt tag config  osaft-NO   -background orange;
    $txt tag config  osaft-HIGH -background lightgreen;
    $txt tag config  osaft-WEAK -background red;
    $txt tag config  osaft-WARN -background lightyellow;
    $txt tag config  osaft-CMT  -foreground gray -underline 1 -font osaftBold;
    $txt tag config  osaft-DBX  -foreground blue;
    $cfg(NOTE) select $tab_run
    set cfg(INFO) "$do done."
}; # osaft_exec

######################################################################### main

set targets ""
foreach arg $argv {
    switch -glob $arg {
        {--v}   { set cfg(VERB) 1; }
        {--h}   -
        {--help} { puts [osaft_about "HELP"]; exit; }
        *       { lappend targets $arg; }
        default { puts "**WARNING: unknown parameter '$arg'; ignored" }
    }
}

wm title        . $cfg(TITLE)
wm iconname     . [string tolower $cfg(TITLE)]
wm geometry     . 600x600

font create osaftBold   {*}[font configure TkDefaultFont] -weight bold
option add *Button.font osaftBold;  # if we want buttons more exposed
option add *Label.font  osaftBold;  # ..
option add *Text.font   TkFixedFont;

## create About window
set cfg(ABOUT) [create_window {About} "570x432"];
destroy $cfg(ABOUT).f1.s;       # no catch{}, so we're informed when code is changed
wm iconify $cfg(ABOUT)
set t [create_text $cfg(ABOUT) [osaft_about "ABOUT"]];
$t.t configure -bg gold;        # dirty hack: widget hardcoded

set w ""

pack [frame $w.ft0]; # create dummy frame to keep create_host() happy

## create command buttons for simple commands and help
pack [frame     $w.fc] -expand 1 -fill x
pack [button    $w.fc.bq -text {Quit}  -bg orange -command {exit}] -side left
pack [button    $w.fc.bs -text {Start} -bg yellow -command "osaft_exec $w.fc {Start}"] -side left
set c 0; # used to change color
foreach b $cfg(FAST) { create_cmd $w.fc $b $c; incr c }
set help [create_help]
pack [button    $w.fc.bh -text {?} -command "wm deiconify $help"] -side right
create_tip      $w.fc.bh "Open window with complete help"
create_tip      $w.fc.bq "Close program"
create_tip      $w.fc.bs "Start $cfg(SAFT) with commands selected in 'Commands' tab"

## create notebook and set up Ctrl+Tab traversal
set cfg(NOTE)   $w.note
ttk::notebook   $cfg(NOTE) -padding 5
ttk::notebook::enableTraversal $cfg(NOTE)
pack $cfg(NOTE) -fill both -expand 1

## create TABs
set tab_cmds    [create_note $cfg(NOTE) {Commands}]
set tab_opts    [create_note $cfg(NOTE) {Options}]

create_opts $tab_cmds {CMD};    # fill Commands pane
create_opts $tab_opts {OPT};    # fill Options pane
# add Save and reset button in Options pane
pack [button    $tab_opts.bs -text {Save}  -command {osaft_save "CFG" 0} -bg lightgreen] -side left
pack [button    $tab_opts.br -text {reset} -command {osaft_reset; osaft_init;}] -side left
osaft_init;                     # initialise options from .-osaft.pl
create_tip      $tab_opts.bs "Save configuration to file"
create_tip      $tab_opts.br "Reset configuration to values from $cfg(INIT)"

## create status line
pack [frame     $w.fl -relief sunken -borderwidth 1] -expand 1 -fill x
pack [label     $w.fl.l -textvariable cfg(INFO) -bg wheat] -expand 1 -fill x -side left

## add hosts from command line
foreach host $targets {         # display hosts
    if {$hosts(0) > 5} { puts "**WARNING: only 6 hosts possible; '$host' ignored"; continue };
    create_host $w
    set hosts($hosts(0)) $host
}
create_host $w

