<?php
#?
#? NAME
#?      $0 - simple wrapper for o-saft.cgi
#?
#? WARNING ####################################################################
#?      This is not tamper-proof code.                                       ##
#?      It passes all received parameters unmodified "as is" to the shell.   ##
#?      Hence this script may be subject to code injections.                 ##
#?                                                                           ##
#?                          You have been warned!                            ##
#?                                                                           ##
#? ############################################################################
#?
#? DESCRIPTION
#?      PHP wrapper to call  o-saft.cgi.  All arguments are passed thru.
#?      The purpose is to support  o-saft.cgi  on web servers which have not
#?      enabled perl as  CGI, or if it is not possible to configure a proper
#?      handler for perl.
#?
#? VERSION
#?      @(#) o-saft.php 1.4 19/11/09 09:25:46
#?
#? AUTHOR
#?      17-feb-17 Achim Hoffmann
# -----------------------------------------------------------------------------

if (empty($_SERVER['QUERY_STRING'])) {
    header("HTTP/1.1 406 Not Acceptable");
    exit(2);
}
# NOTE: cd to directory which contains RC-file .o-saft.pl also
$dir = "../cgi-bin";                            # where to find o-saft.[cgi|pl]
passthru("cd ../cgi-bin;./o-saft.cgi", $err);   # pass QUERY_STRING as is
exit(0);


#_________________________________________ alternate methods, NOT RECOMMENDED _

header('Content-Type: text/plain');
$qs  = "";
if (isset($_SERVER['QUERY_STRING'])) {
    $qs = join(' ', preg_split('/&/', $_SERVER['QUERY_STRING']));
}

$qs  = preg_replace('/[;&`>!|$<]/', '', $qs, -1);# remove just a few dangerous characters
#dbx# echo("cd $dir;./o-saft.pl --cgi $qs \n");
passthru(  "cd $dir;./o-saft.pl --cgi $qs", $err);# pass QUERY_STRING on command line
#dbx# echo "# ERROR: $err\n";
exit(0);

?>
