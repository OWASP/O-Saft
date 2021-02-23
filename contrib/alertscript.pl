#!/usr/bin/perl -w
# Filename: alertscript.pl
#!#############################################################################
#!#             This script is part of the OWASP-Project 'o-saft'
#!# It reads output of ‘CheckAllCiphers.pl’ or ‘osaft.pl’ in csv-format and
#!# rates all findings about TLS protocols, ciphers and TLS parameters
#!# according the configuration in ‘alertscript.cfg’
#!#
#!#----------------------------------------------------------------------------
#!#    Developed as part of a bachelor thesis by Benedikt Gabler
#!# “Identifikation und Adressierung schwacher TLS-Einstellungen
#!#                in lokalen Unternehmensnetzwerken“
#!#  (Identification and Addressing of weak TLS Configurations
#!#                    in Corporate Networks)
#!#
#!#        Hochschule für angewandte Wissenschaften München
#!#        (University of Applied Sciences, Munich, Germany)
#!#                    https://www.cs.hm.edu
#!# Supervising Professor: Prof. Dr. Peter Trapp
#!# In cooperation with Torsten Gigler and Florian Bockamp, BayernLB
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

use strict;
use warnings;
use Carp;                                           #replaces warn and die

my $cfgfile   = "alertscript.cfg";
my $csvfile   = "report.csv";
my $alertfile = "alertfile.txt";

my $line = "";
my $debug = 0; #0: kein debug - 1: debug - 2: big debug

my $cfg_tokens = ["CIPHER","CRIT"];
my $scan_token;

my @prio_array = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO");
my @token_array = ("PROTOCOL", "ORDER", "CIPHER", "PARAM");

my %cfg_hash = ();
my %result_hash = ();

my ($token, $regex, $order,  $value, $ipadress, $port, $prot, $cipher2, $param, $descript) = "";

my $me  = $0; 
$me     =~ s#.*(?:/|\\)##;

sub printhelp {
    print << "EoT";
NAME
    $me - simple rating of protocols, ciphers and parameters based on the output of checkAllCiphers.pl (is part of osaft)
          A configuation file defines the rating and the responsables by the port.
          This script generates an alert file that may be used to generate tickets in a workflow application.
          Consider to use different config files according the protection needs of your applications and how exposed these applications are.

SYNOPSIS
    $me [OPTIONS]

OPTIONS
    --help                this help (also: --h, all options may use '-' or '--' as prefix)

    --cfg=CFGFILE         change the name of the configfile (default is 'alertscript.cfg')
    --cfgfile=CFGFILE     dito

    --csv=CSVFILE         change the name of the inputfile  (default is 'report.csv')
    --csvfile=CSVFILE     dito (also: --in=..., --infile=..., --inputfile=...)

    --alert=ALERTFILE     change the name of the outputfile (default is 'alertfile.txt')
    --alertfile=ALERTFILE dito (also: --out=..., --outfile=..., --outputfile=...)

    --debug=LEVEL         set debug level (default is 0: off; 1: nomal, 2: huge)
    --d=LEVEL             dito (also --d => --d=1, --d --d => --d=2)
EoT
return;
} # printhelp


#Subroutine für das Speichern der Alerts
#Der Subroutine werden 8 Parameter übergebenen
#Ip-Adresse, Port, Priorität, Protokoll, Cipher-Suite, Grund des Alerts, Wert und die Description
sub store_alert ($$$$$$$$) {
    my ($ipadress, $port, $prio, $prot, $cipher, $reason, $value, $descript) = @_;
    my @layer_array = ("OS", "APP");
    my $layer = $layer_array[1];            #Default = "APP"
    print "ALERT [$ipadress, $port, $prio, $prot, $cipher, $reason, $value, $descript]" if ($debug);
    SEARCHLAYER: foreach my $layer_key (@layer_array) {
        foreach (@{$cfg_hash{LAYER}{$layer_key}{regex}}) {
            my $regex = $_ ;
            print "$regex: " if ($debug);
            if ($port =~ /$regex/) {
                print "LAYER: $layer_key\n" if ($debug);
                $layer = $layer_key;
                last SEARCHLAYER;
            }
        }
    }
    push (@{$result_hash{$ipadress}{$layer}{$port}{$prio}{$reason}{$prot}{$cipher}{value}},$value);
    push (@{$result_hash{$ipadress}{$layer}{$port}{$prio}{$reason}{$prot}{$cipher}{descript}},$descript);
    print "STORE INTO:\$result_hash\[$ipadress\]\[$layer\]\[$port\]\[$prio\]\[$reason\]\[$prot\]\[$cipher\]\[value\]: $value\n" if ($debug);
    print "STORE INTO:\$result_hash\[$ipadress\]\[$layer\]\[$port\]\[$prio\]\[$reason\]\[$prot\]\[$cipher\]\[descript\]: $descript\n" if ($debug);

}

#Subroutine zur Ausgabe der im Hash gespeicherten Werte aus der store_alert Subroutine
#Verbose Ausgabe
sub print_all_alerts() {
    my $count = 0;
    print "PRINT ALL ALERTS/AUSGABE ALLER ALERTS:\n";
    foreach my $ipadress (sort keys %result_hash) {
        print "IP: $ipadress\n";
        foreach my $layer (sort {lc $a cmp lc $b} keys %{$result_hash{$ipadress}}) {
            print "LAYER: $layer\n";
            foreach my $port (sort {$a <=> $b} keys %{$result_hash{$ipadress}{$layer}}) {
                print "PORT: $port\n";
                foreach my $prio (@prio_array) {
                    print "PRIO: $prio\n";
                    foreach my $reason (@token_array) {
                    print "REASON: $reason\n";
                        foreach my $prot (sort {lc $a cmp lc $b} keys %{$result_hash{$ipadress}{$layer}{$port}{$prio}{$reason}}) {
                            print "PROTOKOLL: $prot\n";
                            foreach my $cipher (sort {lc $a cmp lc $b} keys %{$result_hash{$ipadress}{$layer}{$port}{$prio}{$reason}{$prot}}) {
                                print "CIPHER: $cipher\n";
                                if (defined $result_hash{$ipadress}{$layer}{$port}{$prio}{$reason}{$prot}{$cipher}{value}) {
                                    $count = @{ $result_hash{$ipadress}{$layer}{$port}{$prio}{$reason}{$prot}{$cipher}{value}};
                                    print "COUNT = $count\n";
                                    for(my $j = 0; $j < $count; $j++) {

                                        print "\$result_hash\[$ipadress\]\[$layer\]\[$port\]\[$prio\]\[$reason\]\[$prot\]\[$cipher\]\[value\]: $result_hash{$ipadress}{$layer}{$port}{$prio}{$reason}{$prot}{$cipher}{value}[$j]\n";
                                        print "\$result_hash\[$ipadress\]\[$layer\]\[$port\]\[$prio\]\[$reason\]\[$prot\]\[$cipher\]\[descript\]: $result_hash{$ipadress}{$layer}{$port}{$prio}{$reason}{$prot}{$cipher}{descript}[$j]\n";

                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        print "\n";
    }
}


#Subroutine mit sortierten Alerts
sub print_sorted_alerts() {
    my $descript_sep = " | ";
    my $count = 0;
    my $sep_counter = 0;
    my $alert = 0;
    print "AUSGABE ALERTS:\n" if ($debug);
    foreach my $ipadress (sort keys %result_hash) {
        print "IP: $ipadress\n" if ($debug);
        foreach my $layer (sort {lc $a cmp lc $b} keys %{$result_hash{$ipadress}}) { #Sortierung nach Werten
            print "LAYER: $layer\n" if ($debug);
            foreach my $port (sort {$a <=> $b} keys %{$result_hash{$ipadress}{$layer}}) { #Sortierung nach Werten
                print "PORT: $port\n" if ($debug);
                foreach my $prio (@prio_array) {
                    print "PRIO: $prio\n" if ($debug);
                    $alert = ($cfg_hash{ALERT}{$prio}{regex}[0] eq "yes");
                    print "Alert: $alert (0: no - 1: yes)\n" if ($debug);
                    foreach my $reason (@token_array) {
                        print "REASON: $reason\n" if ($debug);
                        PROTOCOL: foreach my $prot (sort {lc $a cmp lc $b} keys %{$result_hash{$ipadress}{$layer}{$port}{$prio}{$reason}}) {
                            print "PROTOKOLL: $prot\n" if ($debug);
                            foreach my $cipher (sort {lc $a cmp lc $b} keys %{$result_hash{$ipadress}{$layer}{$port}{$prio}{$reason}{$prot}}) {
                                print "CIPHER: $cipher\n" if ($debug);
                                if (defined $result_hash{$ipadress}{$layer}{$port}{$prio}{$reason}{$prot}{$cipher}{descript}) {
                                    $count = @{ $result_hash{$ipadress}{$layer}{$port}{$prio}{$reason}{$prot}{$cipher}{descript}};
                                    print "COUNT = $count\n" if ($debug);
                                    print ALERTFILE "$ipadress, $layer, $port, $prio, $reason, $result_hash{$ipadress}{$layer}{$port}{$prio}{$reason}{$prot}{$cipher}{value}[0], " if ($alert);
                                    if ($reason eq "PARAM") { #Parameter je Cipher melden
                                        print ALERTFILE "Cipher: $cipher: " if ($alert);
                                    }
                                    for(my $j = 0; $j < $count; $j++) {
                                        print "\$result_hash\[$ipadress\]\[$layer\]\[$port\]\[$prio\]\[$reason\]\[$prot\]\[$cipher\]\[value\]: $result_hash{$ipadress}{$layer}{$port}{$prio}{$reason}{$prot}{$cipher}{value}[$j]\n" if ($debug);
                                        print "\$result_hash\[$ipadress\]\[$layer\]\[$port\]\[$prio\]\[$reason\]\[$prot\]\[$cipher\]\[descript\]: $result_hash{$ipadress}{$layer}{$port}{$prio}{$reason}{$prot}{$cipher}{descript}[$j]\n" if ($debug);
                                        print ALERTFILE "$descript_sep" if (($j>0) and ($alert));
                                        print ALERTFILE "$result_hash{$ipadress}{$layer}{$port}{$prio}{$reason}{$prot}{$cipher}{descript}[$j]" if ($alert);
                                    }
                                    #Gibt alle Protokolle mit benutztem Cipher aus
                                    if (($reason eq "CIPHER") or ($reason eq "ORDER") or ($reason eq "PARAM")) {
                                        print ALERTFILE " [used with protocols: " if ($alert);
                                        $sep_counter = 0;
                                        for my $used_prot (sort {lc $a cmp lc $b} keys %{$result_hash{$ipadress}{$layer}{$port}{$prio}{$reason}}) {
                                            if (defined $result_hash{$ipadress}{$layer}{$port}{$prio}{$reason}{$used_prot}{$cipher}{value}) {
                                                print ALERTFILE "$descript_sep" if (($sep_counter > 0) and ($alert));
                                                print ALERTFILE "$used_prot" if ($alert);
                                                $sep_counter++;
                                                $result_hash{$ipadress}{$layer}{$port}{$prio}{$reason}{$used_prot}{$cipher}{value} = undef;
                                                $result_hash{$ipadress}{$layer}{$port}{$prio}{$reason}{$used_prot}{$cipher}{descript} = undef;
                                            }
                                        }
                                        print ALERTFILE "]" if ($alert);
                                    }
                                    print ALERTFILE "\n" if ($alert);
                                    last PROTOCOL if ($reason eq "ORDER"); #Letzter Cipher (Cipher überspringen wenn Ordnung nicht durch Server vorgegeben wird)
                                    last if ($reason eq "PROTOCOL");
                                }
                            }
                        }
                    }
                }
            }
        }
        print "\n" if ($debug);
    }
}


### main routine #######################################################################################################
# scan options and arguments
my $arg = "";
while ($#ARGV >= 0) {
    $arg = shift @ARGV;
    if ($arg =~ /^-?-h(?:elp)?$/i)                      { printhelp();        exit 0;   } # allow -h -help --h --help
    if ($arg =~ /^-?-cfg(?:file)?=(.*)$/i)              { $cfgfile      = $1; next;     } # cfg=CFGFILE_NAME
    if ($arg =~ /^-?-csv(?:file)?=(.*)$/i)              { $csvfile      = $1; next;     } # csv=CSVFILE_NAME
    if ($arg =~ /^-?-in(?:put)?(?:file)?=(.*)$/i)       { $csvfile      = $1; next;     } # in=CSVFILE_NAME
    if ($arg =~ /^-?-alert(?:file)?=(.*)$/i)            { $alertfile    = $1; next;     } # alert=ALERTFILE_NAME
    if ($arg =~ /^-?-out(?:put)?(?:file)?=(.*)$/i)      { $alertfile    = $1; next;     } # out=ALERTFILE_NAME
    if ($arg =~ /^-?-d(?:ebug)?=(\d)$/i)                { $debug        = $1; next;     } # d=DEBUGLEVEL
    if ($arg =~ /^-?-d(?:ebug)?$/i)                     { $debug       += 1;  next;     } # d+=1
    carp ("**WARNING: unknown command or option '$arg' ignored. Try '$me --help' to get more information!");
    exit 0;
} # while

open (DATEI, $cfgfile) or die $!;
open (ALERTFILE,'>', $alertfile) or die $!;

print "$me:\nRead config file '$cfgfile'\n";
while ($line = <DATEI>) {                                           #Zeilenweises einlesen der Bewertungsdatei-Einträge
    chomp($line);                                                   #Newline am Ende löschen
    if ($line =~ /^\s*(?:#.*)?$/) {                                 #Leerzeilen und Kommentarzeilen überspringen
        next;
    }
    elsif ($line =~ /^(.*?)\s*,\s*((?:dh,|.)*?)\s*,\s*(.*?)\s*,\s*(.*?)(?:\s*#.*)?\r?$/) {     #zeile parsen mit regulären ausdrücken. Es werden nur Zeilen verarbeitet, die mit drei Kommas getrennt werden und in dieser Form vorkommen.
        $token = $1;                                                #Token kann ALERT/CIPHER/PROTOCOL/PARAM/LAYER sein.
        $regex = $2;                                                #regex kann entweder ein Cipherstring/DHParameter/Protokollbezeichnung/einzelnes Verfahren/Port/Alertinfo sein.
        $value = $3;                                                #value kann Kritikalität (info/low/medium/high/critical) oder Layer (APP/OS) sein.
        $descript = $4;                                             #Beschreibung der Zeile.
        print ">$1<, >$2<, >$3<, >$4<\n" if ($debug > 1);
        $token = uc($token);                                        #Umwandeln der Zeichen des Strings in Großbuchstaben.
        $value = uc($value);                                        #Umwandeln der Zeichen des Strings in Großbuchstaben.
    push (@{$cfg_hash{$token}{$value}{regex}}, $regex);             #configwerte in 3-dim hash für token und value abspeichern
    push (@{$cfg_hash{$token}{$value}{descript}}, $descript);
    }
    else {
        warn(">>> Error in configfile: $line");                     #Warnung wird ausgegeben, wenn die Zeile nicht dem definierten Muster entspricht.
    }
}
close (DATEI);

if ($debug) {
    print "Config start\n\n";
    foreach my $token_key (sort keys %cfg_hash) {
        foreach my $prio_key (keys %{ $cfg_hash{ $token_key} }) {
            print "$token_key, $prio_key: [";
            for (my $_i=0; $_i < (@{$cfg_hash{$token_key}{$prio_key}{regex}}); $_i++) {
                print ", " if ($_i > 0);
                print $cfg_hash{$token_key}{$prio_key}{regex}[$_i] . ": " 
                    . $cfg_hash{$token_key}{$prio_key}{descript}[$_i];
            }
            print "]\n";
        }
    }
    print "Config end\n\n";
}

print "Analyze '$csvfile'\n";
open (DATEI2, $csvfile) or die $!;
while ($line = <DATEI2>) {
    chomp($line);                                                   #Newline am Ende löschen
    if ($line =~ /^(.*?)\s*,\s*(.*?)\s*,\s*(.*?)\s*,\s*(.*?)\s*,\s*(.*?)\s*,\s*(.*?)\s*,\s*(.*?)\s*,\s*(.*?)\s*(?:,\s*(.*?)\s*)?\r?$/) {       # =~ /.../=REGEX, ^=Zeilenanfang, ()=gefundener Wert in Variable $1-... speichern, .=beliebiges Zeichen, *=0...x mal, *?=0...x mal nicht gierig (nur bis zum komma inkl optionalen leerzeichen), \s=leerzeichen (space/tab), das komma vor $9 ist optional, \r=Wagenrücklauf=carriage return (Windows) $=Zeilenende
        $ipadress = $1;
        $port = $2;
        $prot = $3;
        $order = $5;
        $cipher2 = $8;
        if (defined $9) {
            $param = $9;
        }
        else {
            $param = "";
        }
        $cipher2 = uc($cipher2);
        print ">$1<, >$2<, >$3<, >$4<, >$5<, >$6<, >$7<, >$cipher2<, >$param<\n" if ($debug > 1);

        #Auswertung der Testergebnisse
        foreach my $token_key (@token_array) {      #Schleife prüft das Ergebnis nach PROTOCOL, CIPHER und PARAM vergleiche @token_array
            foreach my $prio_key (@prio_array) {
                print "$token_key, $prio_key: [" if ($debug);
                my $i = 0;
                foreach (@{ $cfg_hash{$token_key}{$prio_key}{regex}}) {
                    my $regex = $_ ;
                    my $descript = $cfg_hash{$token_key}{$prio_key}{descript}[$i];
                    $i++;
                    print "$regex: " if ($debug);
                    if ($token_key eq "PROTOCOL") { #Regex je nach Tokentyp mit der passenden Spalte vergleichen
                        if ($prot =~ /$regex/) {
                            print "ALERT $prot $prio_key $ipadress $port $descript\n" if ($debug);
                            store_alert($ipadress, $port, $prio_key, $prot, $cipher2, $token_key, $prot, $descript);
                        }
                    }
                        elsif ($token_key eq "ORDER") {
                        if ($order =~ /$regex/) {
                            print "ALERT $order $prio_key $ipadress $port $descript\n" if ($debug);
                            store_alert($ipadress, $port, $prio_key, $prot, $cipher2, $token_key, $order, $descript);
                        }
                    }
                        elsif ($token_key eq "CIPHER") {
                        if ($cipher2 =~ /$regex/) {
                            print "ALERT $cipher2 $prio_key $ipadress $port $descript\n" if ($debug);
                            store_alert($ipadress, $port, $prio_key, $prot, $cipher2, $token_key, $cipher2, $descript);
                        }
                    }
                        elsif ($token_key eq "PARAM") {
                        if ($param =~ /$regex/) {
                            print "ALERT $param $prio_key $ipadress $port $descript\n" if ($debug);
                            store_alert($ipadress, $port, $prio_key, $prot, $cipher2, $token_key, $param, $descript);
                        }
                    }
                }
                print "]\n" if ($debug);
            }
        }
        print "\n" if ($debug);
    }
}

close (DATEI2);
print "Analyze end\n" if ($debug);
print_all_alerts() if ($debug >1);
print_sorted_alerts();
close (ALERTFILE);
print "Alerts written in '$alertfile'\n";

