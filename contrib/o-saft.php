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
#?      handler for perl but allows PHP.
#?      o-saft.cgi or o-saft.pl  will be search for in various paths related
#?      to $_SERVER['SCRIPT_FILENAME'].
#?
#? VERSION
#?      @(#) o-saft.php 1.5 19/11/09 11:49:52
#?
#? AUTHOR
#?      17-feb-17 Achim Hoffmann
# -----------------------------------------------------------------------------

function get_exe($base, $file, $dirs) {
    $exe = $file;   # fallback
    foreach ($dirs as $dir) {
        #$exe = realpath(os.path.join($base, $dir, $file));
            # NOTE: os.path not used to avoid include of os
        $exe = realpath(join(DIRECTORY_SEPARATOR, [$base, $dir, $file]));
        if (! empty($exe)) { break; }   # got it
    }
    return $exe;
}

# list of directories where to search for o-saft.[cgi|pl] ; first one wins
# NOTE: */O-Saft and ../ used for easy testing in development environment,
#       can/should be removed in production
$dirs = array('.', 'cgi-bin', '../cgi-bin', 'O-Saft', 'cgi-bin/O-Saft', '../cgi-bin/O-Saft', '..');
$path = pathinfo( $_SERVER['SCRIPT_FILENAME']); # analyze myself

if (empty($_SERVER['QUERY_STRING'])) {
    header("HTTP/1.1 406 Not Acceptable");
    exit(2);
}

$cgi  = get_exe($path['dirname'], 'o-saft.cgi', $dirs);
$path = pathinfo($cgi);     # need to start in directory so that .o-saft.pl is used
$call = join(' ', ['cd', $path['dirname'], ';', $path['basename'] ]);
passthru("$call", $err);
exit(0);

#_________________________________________ alternate methods, NOT RECOMMENDED _

header('Content-Type: text/plain');
$qs   = "";
if (isset($_SERVER['QUERY_STRING'])) {
  $qs = join(' ', preg_split('/&/', $_SERVER['QUERY_STRING']));
}
$qs   = preg_replace('/[;&`>!|$<]/', '', $qs, -1);# remove just a few dangerous characters
$exe  = get_exe($path['dirname'], 'o-saft.pl', $dirs);
$call = join(' ', ['cd', $path['dirname'], ';', $path['basename'], '--cgi', $qs]);
#dbx# echo("call=$call\n");
passthru(  "$call", $err);  # pass QUERY_STRING on command line
#dbx# echo "# ERROR=$err\n";
exit(0);

?>
