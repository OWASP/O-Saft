<?php
#?
#? NAME
#?      $0 - simple wrapper for o-saft.pl
#?
#? WARNING ####################################################################
#?      This is not tamper-proof code.                                       ##
#?      It passes all received parameters unmodified "as is" to the shell.   ##
#?      Just a few known dangerous characters are removed.                   ##
#?      Hence this script may be subject to code injections.                 ##
#?                                                                           ##
#?                          You have been warned!                            ##
#?                                                                           ##
#? ############################################################################
#?
#? DESCRIPTION
#?      PHP wrapper to call  o-saft.pl.  All arguments are passed thru.
#?      The purpose is to support  o-saft.pl  on web servers which have not
#?      enabled perl as CGI, or if it is not possible to configure a proper
#?      handler for perl.
#?
#? LIMITATIONS
#?      The special characters  ; & ` > ! | $ <  in parameters are silently
#?      removed. This is a simple, but not perfect attempt to inhibit shell
#?      injections.
#?
#? VERSION
#?      @(#) o-saft.php 1.2 18/09/30 23:28:13
#?
#? AUTHOR
#?      17-feb-17 Achim Hoffmann
# -----------------------------------------------------------------------------

header('Content-Type: text/plain');
$qs = "";
if (isset($_SERVER['QUERY_STRING'])) {
    $qs = join(' ', split('&', $_SERVER['QUERY_STRING']));
}
$qs = preg_replace('/[;&`>!|$<]/', '', $qs, -1);# remove dangerous characters
#dbx# echo("/cgi-bin/o-saft.pl --cgi $qs \n");
#passthru("/cgi-bin/o-saft.pl --cgi $qs", $err);
passthru("cd ../cgi-bin;./o-saft.pl $qs", $err);
        # --cgi avoids messages like:  "=== reading: ..."
        # add more options as needed
#dbx# echo "# ERROR: $err\n";
exit;

?>
