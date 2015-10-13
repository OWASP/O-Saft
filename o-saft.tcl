#!/usr/bin/wish
# restarts using wish \
exec wish "$0" --

## above exec quick&dirt for Mac OS X, below would be better
##  exec wish "$0" ${1+"$@"}

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
#? DESCRIPTION
#?      This is a simple GUI for  O-Saft - OWASP SSL advanced forensic tool.
#?      The GUI supports all commands and options available in  o-saft.pl.
#?      It executes  o-saft.pl  as specified, and prints results in a new  TAB
#?      of the GUI. Results and settings (commands and options) can be saved.
#?
#? SYNOPSIS
#?      $0 [host:port] [host:port] ...
#?
#? OPTIONS
#?      --v  print verbose messages (for debugging)
#?
#? ARGUMENTS
#?      All arguments, except --help, are treated as a hostname to be checked.
#?
#. LAYOUT
#.           +---------------------------------------------------------------+
#.       (H) | Host:Port [________________________________________]  [+] [-] |
#.           |                                                               |
#.       (C) | [Start] [+info] [+check] [+cipher] [+quick] [+vulns]      [?] |
#.           |---------------------------------------------------------------|
#.           | +----------++---------++----------++----------+               |
#.       (T) | | Commands || Options || (n) +cmd || (m) +cmd |               |
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
#.       (T) - Frame containing panes for commands options, and results
#.       (S) - Frame containing Status messages
#.
#. HACKER's INFO
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
#.
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
#?      @(#) 1.19 Sommer Edition 2015
#?
#? AUTHOR
#?      04. April 2015 Achim Hoffmann (at) sicsec de
#?
# -----------------------------------------------------------------------------

package require Tcl     8.5
package require Tk      8.5

set cfg(SID)    {@(#) o-saft.tcl 1.19 15/10/13 21:38:36 Sommer Edition 2015}
set cfg(TITLE)  {O-Saft}

set cfg(TIP)    [catch { package require tooltip} tip_msg];  # 0 on success, 1 otherwise!

set cfg(PERL)   {};             # full path to perl; empty on *nix
if {[regexp {indows} $tcl_platform(os)]} {
    # Some platforms are too stupid to run our executable cfg(SAFT) directly,
    # they need a proper perl executable to do it. We set a default path and
    # then check if it is executable. If it is not, ask the user to choose a
    # proper one.  There are no more checks for the selected file.  If it is
    # wrong, the script will bail out with an error later.
    set cfg(PERL)   {c:/programs/perl/perl/bin/perl.exe}
    if {![file executable $cfg(PERL)]} {
        set cfg(PERL) [tk_getOpenFile -title "Please choose perl.exe" ]
    }
}
# NOTE: as Tcl is picky about empty variables, we have to ensure later, that
# $cfg(PERL) is evaluated propperly, in particular when it is empty.  We use
# Tcl's  {*}  evaluation for that.

#-----------------------------------------------------------------------------{
#   CONFIGURATION
#   this is the only section where we know about o-saft.pl
#   all settings for o-saft.pl go here
set cfg(SAFT)   {o-saft.pl};    # name of O-Saft executable
set cfg(INIT)   {.o-saft.pl};   # name of O-Saft's startup file
set cfg(.CFG)   {}; # set below
set cfg(geoS)   "600x600";      # geometry and position of O-Saft window
set cfg(geoA)   "600x425";      # geometry and position of About  window
set cfg(geoH)   "600x775-0+0";  # geometry and position of Help   window
catch {
  set fid [open $cfg(INIT) r]
  set cfg(.CFG) [read $fid];   close $fid;          # read .o-saft.pl
}
#   now get information from O-Saft; it's a performance penulty, but simple ;-)
catch { exec {*}$cfg(PERL) $cfg(SAFT) +help }           cfg(HELP)
catch { exec {*}$cfg(PERL) $cfg(SAFT) --help=opt }      cfg(OPTS)
catch { exec {*}$cfg(PERL) $cfg(SAFT) --help=commands } cfg(CMDS)
set cfg(FAST)   {{+check} {+cipher} {+info} {+quick} {+vulns}}; # quick access commands
#-----------------------------------------------------------------------------}

#   internal data storage
set cfg(CDIR)   [file join [pwd] [file dirname [info script]]]
set cfg(INFO)   ""; # text to be used in status line
set cfg(EXEC)   0;  # count executions, used for object names
set cfg(x--x)   0;  # each option  will have its own entry (this is a dummy)
set cfg(x++x)   0;  # each command will have its own entry (this is a dummy)
set cfg(objN)   ""; # object name of notebook; needed to add more note TABS
set cfg(winA)   ""; # object name of About window
set cfg(winH)   ""; # object name of Help  window
set cfg(POSY)   [winfo y .];    # used to position other windows
set cfg(POSX)   [winfo x .]; incr cfg(POSX) 100;
set cfg(VERB)   0;  # set to 1 to print more informational messages from Tcl/Tk
set hosts(0)    0;  # array containing host:port; index 0 contains counter
set tab(0)      ""; # contains results of cfg(SAFT)

######################################################################## procs

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
}; # isTOC

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
    pack [frame $this.f0  -relief sunken  -borderwidth 1] -fill x -side top
    pack [label $this.f0.l  -text $title  -font TkCaptionFont]    -side left
    pack [frame $this.f1  -relief sunken  -borderwidth 1] -fill x -side bottom
    pack [button $this.f1.q -text "Close" -bg orange -command "destroy $this"] -side right
    create_tip   $this.f1.q "Close Window"
    if {$title ne "Help" && $title ne "About"} {
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
    if {$cfg(VERB)==1} { puts "create_host: host($hosts(0)): " }; # $hosts($hosts(0))
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
        $this.bm configure -text {!} -command "create_about"
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

proc create_see {w t} { catch { $w see [$w index $t.first] } }
     # we simply ignore any error if index is unknown

proc create_about {} {
    #? create new window with About text; store widget in cfg(winA)
    global cfg
    if {[winfo exists $cfg(winA)]}  { show_window $cfg(winA); return; }
    set cfg(winA) [create_window {About} $cfg(geoA)]
    set t [create_text $cfg(winA) [osaft_about "ABOUT"]];
    $t.t configure -bg gold;        # dirty hack: widget hardcoded
}; # create_about

proc create_help {} {
    #? create new window with complete help; store widget in cfg(winH)
    # uses plain text help text from "o-saft.pl --help"
    # This text is parsed for section header line (all capital characters)
    # which will be used as Table of Content and inserted before the text.
    # All referenzes to this sections are clickable.
    # Also all references to commands (starting with '+') and options ('-')
    # are highlighted and used for navigation.
    # Idea: probably "o-saft.pl --help=wiki" is better suitable for creating
    # the help text herein.
    global cfg
    if {[winfo exists $cfg(winH)]}  { show_window $cfg(winH); return; }
    set this    [create_window {Help} $cfg(geoH)]
    set help    [regsub -all {===.*?===} $cfg(HELP) {}];  # remove informal messages
    set txt     [create_text $this $help].t
    set toc     {}

    # 1. search for section head lines, mark them and add (prefix) to text
    set anf [$txt search -regexp -nolinestop -all -count end {^ *[A-Z][A-Z_? -]+$} 1.0] 
    set i 0
    foreach a $anf {
        set e [lindex $end $i];
        set t [$txt get $a "$a + $e c"];
        set l [string length $t]
        incr i
        if {[notTOC $t]} { continue; }; # skip some special strings
        set toc "$toc\n  $t"
        set name [str2obj [string trim $t]]
        $txt tag add  osaft-HEAD       $a "$a + $e c"
        $txt tag add  osaft-HEAD-$name $a "$a + $e c"
        #$txt insert $a "\n\[ ^ \]\n"; # TODO: insert button to top 
    }
    $txt config -state normal
    $txt insert 1.0 "\nCONTENT\n$toc\n\n"
    $txt tag     add  osaft-LNK    2.0 2.7;             # add markup
    $txt tag     add  osaft-LNK-T  2.0 2.7;             #
    $txt config -state disabled
    set nam [$txt search -regexp -nolinestop {^NAME$} 1.0]; # only new insert TOC

    # 2. search for all references to section head lines in TOC and add click event
    set anf [$txt search -regexp -nolinestop -all -count end { *[A-Z_\? -]+( |$)} 3.0 $nam] 
    # FIXME: above regex fails for some lines in generated TOC, reason unknown.
    set i 0
    foreach a $anf {
        set e [lindex $end $i];
        set t [$txt get $a "$a + $e c"];
        if {[notTOC $t]} { continue; }; # skip some special strings
        incr i
        set name [str2obj [string trim $t]]
        set b [$txt search -regexp {[A-Z]+} $a] 
        $txt tag add  osaft-TOC    $b "$b + $e c"; # - 1 c";# do not markup leading spaces
        $txt tag add  osaft-TOC-$i $a "$a + $e c";      # but complete line is clickable
        $txt tag bind osaft-TOC-$i <ButtonPress> "create_see $txt {osaft-HEAD-$name}"
    }

#    # 2a. search for all references to section head in text
#    set anf [$txt search -regexp -nolinestop -all -count end { +[A-Z_ -]+( |$)} $nam]
#    # FIXME: returns too much false positives
#    set i 0
#    foreach a $anf {
#        set e [lindex $end $i];
#        set t [$txt get $a "$a + $e c"];
#        incr i
#        if {[regexp {^[A-Z_ -]+$} $t]} { continue };  # skip headlines itself
#        if {[regexp {HIGH|MDIUM|LOW|WEAK|SSL|DHE} $t]} { continue };  # skip false matches
#        if {[notTOC $t]} { continue; }; # skip some special strings
#        $txt tag add    osaft-XXX $a "$a + $e c"
#        $txt tag bind   osaft-XXX-$i <ButtonPress> "create_see $txt {osaft-LNK-$name}"
#        $txt tag config osaft-XXX    -foreground blue
#    }

    # 3. search all commands and options and try to set click event
    set anf [$txt search -regexp -nolinestop -all -count end { [-+]-?[a-zA-Z0-9_=+-]+([, ]|$)} 3.0] 
    set i 0
    foreach a $anf {
        set e [lindex $end $i];
        set l [$txt get "$a - 2 c" "$a + $e c + 1 c"]; # one char more, so we can detect head line
        set t [string trim [$txt get $a "$a + $e c"]];
        set r [regsub {[+]} $t {\\+}];  # need to escape +
        set r [regsub {[-]} $r {\\-}];  # need to escape -
        set name [str2obj [string trim $t]]
        if {[regexp -lineanchor "\\s\\s+$r$" $l]} {    # FIXME: dos not match all line proper
            # these matches are assumed the header lines
            $txt tag add    osaft-LNK-$name $a "$a + $e c";
            $txt tag add    osaft-LNK       $a "$a + $e c";
        } else {
            # these matches are assumed references
            $txt tag add    osaft-LNK-$i $a "$a + $e c - 1 c"; # do not markup spaces
            $txt tag bind   osaft-LNK-$i <ButtonPress> "create_see $txt {osaft-LNK-$name}"
            $txt tag config osaft-LNK-$i -foreground blue
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
    $txt tag config   osaft-TOC  -foreground blue
    $txt tag config   osaft-HEAD -font osaftBold
    $txt tag config   osaft-TOC  -font osaftBold
    $txt tag config   osaft-LNK  -font osaftBold
    $txt tag config   osaft-CODE -background lightgrey

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
    pack [button $this -text $title -bg "gold$color" -command "osaft_exec $parent $title"] -side left
    create_tip   $this "Execute $cfg(SAFT) with command $title"
    return $this
}; # create_cmd

proc create_win {parent cmd title} {
    #? create window for commands and options
    #  creates one button for each line returned by: o-saft.pl --help=opt|commands
    # title must string of group of command or options
    global cfg
    set this $parent
    set grp  $this
    set data $cfg(OPTS)
    if {$cmd eq "CMD"} { set data $cfg(CMDS) }
    set max  0; # FIXME: quick&dirty fix to avoid huge windows
    set cnt  0; # FIXME: ..
    set txt  "";# FIXME: ..
    set skip 1; # skip data until $title found
    foreach l [split $data "\r\n"] {
        set dat [string trim $l]
        if {[regexp {^(Commands|Options)} $dat]} { set skip 1; };    # next group starts
        if {[regexp "$title" $dat]}        { set skip 0; }
        if {$skip == 1}                    { continue; }
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
        if {[regexp {^[^+-]} $dat] || $max > 33} {
            if {$max > 33} { incr cnt; set dat $txt }
            # remove noicy prefix and make first character upper case
            set dat [string toupper [string trim [regsub {^(Commands|Options) (to|for)} $dat ""]] 0 0]
            set max  0
            set hoch 450
            #set name [str2obj $dat]$cnt
            set name [str2obj "$dat $cnt"]; # same as in create_window
            incr cfg(POSX) 25;
            incr cfg(POSY) 25;
            if {[regexp {(checked|SSL) connection} $dat]} { set hoch 680 }; # <<== dirty hack ;-(
            set grp  [create_window "$dat $cnt" "300x$hoch+$cfg(POSX)+$cfg(POSY)"]
            if {$cfg(VERB)==1} { puts "create_win: $grp" }
            continue
        }
        incr max
        set tip [lindex [split $dat "\t"]  1]
        set dat [lindex [split $dat " \t"] 0]
        if {$cfg(VERB)==1} { puts "create_win: create: $cmd >$dat<" }
        set name [str2obj $dat]
        if {[winfo exists $grp.$name]} {
            if {$cfg(VERB)==1} {puts "**WARNING: create_win exists: $grp.$name"};
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
        create_tip $grp.$name "$tip";   # $tip may be empty, i.e. for options
    }
}; # create_win

proc create_button {parent cmd} {
    #? create buttons to open window with commands or options
    #  creates one button for header line returned by: o-saft.pl --help=opt|commands
    # cmd must be "OPT" or "CMD" or "TRC"
    global cfg
    set data $cfg(OPTS)
    if {$cmd eq "CMD"} { set data $cfg(CMDS) }
    foreach l [split $data "\r\n"] {
        set txt [string trim $l]
        if {[regexp {^(Commands|Options|General) } $txt] == 0} { continue }
        ## skipped general
        if {$txt eq ""}                    { continue; }
        if {[regexp {^(==|\*\*)}    $txt]} { continue; }; # header or Warning
        if {"OPTIONS" eq $txt}             { continue; }
        # remove noicy prefix and make first character upper case
        set dat  [string toupper [string trim [regsub {^(Commands|Options) (to|for)} $txt ""]] 0 0]
        set name [str2obj $dat]
        set this $parent.$name
        if {$cfg(VERB)==1} { puts "create_button .$name {$txt}" }
        pack [button $this -text $dat -command "create_win .$name $cmd {$txt}" -bg lightyellow ] \
                 -anchor w -fill x -padx 10 -pady 2
        create_tip   $this "Open window with more settings"
    }
}; # create_button

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
        set name [tk_getSaveFile -confirmoverwrite true -title "Save result to file" -initialfile "$cfg(SAFT)--$nr.log"]
        if {$name eq ""} { return }
        set fid  [open $name w]
        puts $fid $tab($nr)
    }
    if {$type eq "CFG"} {
        set name [tk_getSaveFile -confirmoverwrite true -title "Save configuration to file" -initialfile ".$cfg(SAFT)--new"]
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
    set cfg(INFO) "saved to $name"; update idletasks;# enforce display update
}; # osaft_save

proc create_filter {txt} {
    #? apply filters for markup in output
    # we do no use output of "o-saft.pl +help=ourstr" 'cause of better readability
      #------+-------+--+----------------------+-------+---------------+-------+----
      # key   mode    len regex		     foreground	background    underline	font
      #------+-------+--+----------------------+-------+---------------+-------+----
    array set filter {
      {YES}  {-regexp 3  {yes\n}		{}	{lightgreen}	0	{}}
      {CMT}  {-regexp 0  {^==*}			{gray}	{}		1	osaftHead }
      {DBX}  {-regexp 0  {^#[^[]}		{blue}	{}		0	{}}
      {KEY}  {-regexp 2  {^#\[[^:]+:\s*} 	{}	{gray}		0	{}}
      {CMD}  "-regexp 0  {.*?cfg(SAFT).*\\n\\n}	{white}	{black}		0	{}"
      {NO}   {-exact  2  {no (}			{}	{orange}	0	{}}
      {LOW}  {-exact  3  {LOW}			{}	{red}		0	{}}
      {WEAK} {-exact  4  {WEAK}			{}	{red}		0	{}}
      {weak} {-exact  4  {weak}			{}	{red}		0	{}}
      {HIGH} {-exact  4  {HIGH}			{}	{lightgreen}	0	{}}
      {WARN} {-exact  0  {**WARN}		{}	{lightyellow}	0	{}}
    };#------+-------+--+----------------------+-------+---------------+-------+----
        # following would be better, but does not mark summary lines
        # it also marks "yes ", which is not easy to compute
      #{LOW}  {-regexp 4  {yes\s+LOW}		{}	{red}		0	{}}
      #{WEAK} {-regexp 4  {yes\s+WEAK}		{}	{red}		0	{}}
      #{weak} {-regexp 4  {yes\s+weak}		{}	{red}		0	{}}
      #{HIGH} {-regexp 4  {yes\s+HIGH}		{}	{lightgreen}	0	{}}
        #
        # Info zu den RegEx:
        #   Metazeichen mit einem \ muessen eigentlich als \\ geschrieben
        #   werden, meist geht es aber auch so. Es wird \\n benutzt, damit bei
        #   der Debug-Ausgabe ein \n sichtbar ist.
        #   DBX  soll keine Zeilen treffen, die mit einem  KEY  beginnen, also
        #       # [sowas]: ist eine Debug-Zeile
        #       #[irgendwas]: ist eine Zeile die wegen --trace-key so aussieht
        #   KEY  matched  #[irgendwas]: mit den folgenden Whitespace
        #   CMD  benutzt  cfg(SAFT),  das kann so nicht in der Liste definiert
        #        werden, darum wird cfg.SAFT. spaeter nochmal gesetzt
        #
    global cfg
    foreach key [array names filter] {
        set mod [lindex $filter($key) 0]
        set len [lindex $filter($key) 1]; # currenty used for 0 only
        set rex [lindex $filter($key) 2]
        set fg  [lindex $filter($key) 3]
        set bg  [lindex $filter($key) 4]
        set nr  [lindex $filter($key) 5]
        set fn  [lindex $filter($key) 6]
        if {$mod eq ""} { continue };   # disabled filter rules
	set rex [regsub {cfg.SAFT.} $rex $cfg(SAFT)];   # substitute variable
        if {$cfg(VERB)==1} {puts "create_filter: $key : $rex"};
        # anf contains start, end corresponding end position of match
        set anf [$txt search -all $mod -count end "$rex" 1.0] 
        set i 0
        foreach a $anf {
            set e [lindex $end $i];
            incr i
            if {$key eq {NO} || $key eq {YES}} {incr e -1 }; # very dirty hack to beautify print
            if {$len == 0} {
               $txt tag add osaft-$key  $a "$a + 1 line - 1 char"
            } else {
               $txt tag add osaft-$key  $a "$a + $e c"
            }
        }
        #dbx# puts "$key: $rex F $fg B $bg U $nr font $fn"
        if {$fg ne ""}  { $txt tag config osaft-$key -foreground $fg }
        if {$bg ne ""}  { $txt tag config osaft-$key -background $bg }
        if {$nr ne "0"} { $txt tag config osaft-$key -underline  $nr }
        if {$fn ne ""}  { $txt tag config osaft-$key -font       $fn }
    }

}; # create_filter

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
    set execme [list exec {*}$cfg(PERL) $cfg(SAFT) {*}$opt {*}$do {*}$targets]; # Tcl >= 8.5
    set cfg(INFO) "$execme"; update idletasks;      # enforce display update
    incr cfg(EXEC)
    catch {
       #set osaft [eval $execme]; # Tcl < 8.5
        set osaft [{*}$execme];   # Tcl > 8.4
    } exec_msg
    set execme [regsub "^\s*exec\s*" $execme {}];   # pretty print command
    set tab($cfg(EXEC)) "\n$execme\n\n$exec_msg\n"
    set tab_run  [create_note $cfg(objN) "($cfg(EXEC)) $cmd"]
    set txt [create_text  $tab_run $tab($cfg(EXEC))].t ;    # <== ugly hardcoded .t
    pack [button $tab_run.bs -text {Save}  -bg lightgreen -command "osaft_save {TAB} $cfg(EXEC)"] -side left
    pack [button $tab_run.bq -text {Close TAB} -bg orange -command "destroy $tab_run"] -side right
    create_tip   $tab_run.bq "Close window"
    create_tip   $tab_run.bs "Save result to file"
    create_filter $txt ;        # text placed in pane, now do some markup
    $cfg(objN) select $tab_run
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

if {$cfg(VERB)==1} {
    puts "PRG $argv0"
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
    if {[info exists geometry]==1} { puts " |  geometry:  $geometry" }
}

wm title        . $cfg(TITLE)
wm iconname     . [string tolower $cfg(TITLE)]
wm geometry     . $cfg(geoS)

font create osaftHead   {*}[font configure TkFixedFont;]  -weight bold
font create osaftBold   {*}[font configure TkDefaultFont] -weight bold
font create osaftSlant  {*}[font configure TkDefaultFont] -slant italic
option add *Button.font osaftBold;  # if we want buttons more exposed
option add *Label.font  osaftBold;  # ..
option add *Text.font   TkFixedFont;

set w ""

pack [frame $w.ft0]; # create dummy frame to keep create_host() happy

## create command buttons for simple commands and help
pack [frame     $w.fc] -expand 1 -fill x
pack [button    $w.fc.bq -text "Quit"  -bg orange -command {exit}] -side left
pack [button    $w.fc.bs -text "Start" -bg yellow -command "osaft_exec $w.fc {Start}"] -side left
set c 0; # used to change color
foreach b $cfg(FAST) { create_cmd $w.fc $b $c; incr c }
pack [button    $w.fc.bh -text {?} -command "create_help"] -side right
create_tip      $w.fc.bh "Open window with complete help"
create_tip      $w.fc.bq "Close program"
create_tip      $w.fc.bs "Start $cfg(SAFT) with commands selected in 'Commands' tab"

## create notebook object and set up Ctrl+Tab traversal
set cfg(objN)   $w.note
ttk::notebook   $cfg(objN) -padding 5
ttk::notebook::enableTraversal $cfg(objN)
pack $cfg(objN) -fill both -expand 1

## create TABs: Command and Options
set tab_cmds    [create_note $cfg(objN) "Commands"]
set tab_opts    [create_note $cfg(objN) "Options"]
create_button $tab_cmds {CMD}; # fill Commands pane
create_button $tab_opts {OPT}; # fill Options pane

# add Save and Reset button in Options pane
pack [button    $tab_opts.bs -text "Save"  -command {osaft_save "CFG" 0} -bg lightgreen] -side left
pack [button    $tab_opts.br -text "Reset" -command {osaft_reset; osaft_init;}] -side left
osaft_init;     # initialise options from .-osaft.pl (values shown in Options tab)
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

# add one Host: line  with {+} and {!} button
create_host $w

