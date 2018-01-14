#!/usr/bin/perl

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

#!# WARNING:
#!# This is no "academically" certified code,  but written to be understood and
#!# modified by humans (you:) easily.  Please see the documentation  in section
#!# "Program Code"  (file coding.txt) if you want to improve the program.

# NOTE
#       Perl's  `use' and `require' will be used for common and well known Perl
#       modules only. All other modules, in particular our own ones, are loaded
#       using an internal function, see _load_file().  All required modules are
#       included as needed. This keeps away noisy messages and allows to be run
#       and print some information even if installed incompletely.

## no critic qw(InputOutput::RequireEncodingWithUTF8Layer)
#  NOTE:  see .perlcritic for detailed description of "no critic"

## no critic qw(Variables::RequireLocalizedPunctuationVars)
#  NOTE: Perl::Critic seems to be buggy as it does not honor the  allow  option
#        for this policy (see  .perlcriticrc  also).  It even doesn't honor the
#        setting here, hence it's disabled at each line using  $ENV{} = ...

## no critic qw(Variables::ProhibitPackageVars)
#  NOTE: we have a couple of global variables, but do not want to write them in
#        all CAPS (as it would be required by Perl::Critic)

## no critic qw(ErrorHandling::RequireCarping)
#  NOTE: Using carp() is nice in modules,  as it also prints the calling stack.
#        But here it is sufficient to see the line number, hence we use warn().

## no critic qw(Subroutines::ProhibitExcessComplexity)
#  NOTE: It's the nature of checks to be complex, hence don't complain.

## no critic qw(Modules::ProhibitExcessMainComplexity)
#  NOTE: Yes, it's a high, very high complexity here.
#       BUG: this pragma does not work here, needs mccabe value ...

use strict;
use warnings;
use constant { ## no critic qw(ValuesAndExpressions::ProhibitConstantPragma)
    # NOTE: use Readonly instead of constant is not possible, because constants
    #       are used  for example in the  BEGIN section.  Constants can be used
    #       there but not Readonly variables. Hence  "no critic"  must be used.
    SID         => "@(#) yeast.pl 1.777 18/01/14 23:10:01",
    STR_VERSION => "18.01.13",          # <== our official version number
};

sub _set_binmode    {
    # SEE Perl:binmode()
    my $layer = shift;
    binmode(STDOUT, $layer);
    binmode(STDERR, $layer);
    return;
} # _set_binmode
_set_binmode(":unix:utf8"); # set I/O layers very early

our $time0  = time();
sub _yeast_TIME(@)  {
    # print timestamp if --trace-time was given; similar to _y_CMD
    # need to check @ARGV directly as this is called before any options are parsed
    my @txt = @_;
    my $me  = $0; $me =~ s{.*?([^/\\]+)$}{$1};
    my $now = time() - ($time0 || 0);
       #$now =- ($time0 || 0) if (not (grep{/(?:--time.*absolut)/i} @ARGV));
       $now = time() if ((grep{/(?:--time.*absolut)/i} @ARGV));
    if ((grep{/(?:--trace.*time)/i} @ARGV) > 0) {
        printf("#$me %02s:%02s:%02s CMD: %s\n", (localtime($now))[2,1,0], @txt);
    }
    return;
}
sub _yeast_EXIT($)  {
    # exit if parameter matches given argument in @ARGV
    my $txt =  shift;   # example: INIT0 - initialization start
    my $arg =  $txt;
       $arg =~ s# .*##; # strip off anything right of a space
    if ((grep{/(?:([+]|--)$arg).*/i} @ARGV) > 0) {
        printf STDERR ("#o-saft.pl  _yeast_EXIT $txt\n");
        exit 0;
    }
    return;
}

#$DB::single=1;  # for debugging; start with: PERL5OPT='-dt' $0

BEGIN {
    _yeast_TIME("BEGIN{");
    _yeast_EXIT("exit=BEGIN0 - BEGIN start");
    sub _VERSION() { return STR_VERSION; }  # required in o-saft-man.pm
    # SEE Perl:BEGIN , Therefore this scope is used for --help=* options only.

    my $_me   = $0; $_me   =~ s#.*[/\\]##;
    my $_path = $0; $_path =~ s#[/\\][^/\\]*$##;
    unshift(@INC,                   # NOTE that / works here even for Windoze
            "./", "./lib",          # we support some local lib directories
            $_path,                 # user-friendly: add path of myself also
            "/bin",                 # special installation on portable media
    );

    # handle simple help very quickly
    if ((grep{/^(?:--|\+)VERSION/} @ARGV) > 0) { print STR_VERSION . "\n"; exit 0; }
    # be smart to users if systems behave strange :-/
    print STDERR "**WARNING: 019: on $^O additional option  --v  required, sometimes ...\n" if ($^O =~ m/MSWin32/);
    _yeast_EXIT("exit=BEGIN1 - BEGIN end");
} # BEGIN
_yeast_TIME("BEGIN}");              # missing for +VERSION, however, +VERSION --trace-TIME makes no sense
_yeast_EXIT("exit=INIT0 - initialization start");

our $osaft_standalone = 0;  # SEE Note:Stand-alone

## PACKAGES         # dummy comment used by some generators, do not remove

use osaft;          # get most of our configuration; it's ok to die if missing

#_____________________________________________________________________________
#________________________________________________________________ variables __|

our $VERSION= STR_VERSION;
my  $me     = $cfg{'me'};       # use a short and easy to remember variable name
my  $mepath = $0; $mepath =~ s#/[^/\\]*$##;
    $mepath = "./" if ($mepath eq $me);
$cfg{'mename'} = $me;

# now set @INC
# NOTE: do not use "-I . lib/" in hashbang line as it will be pre- and appended
# don't add if $mepath == ./ as it most likely is already part of @INC
# also note that this setting only applies to `require' but not `use' directives
unshift(@INC, "$mepath", "$mepath/lib") ;#if ($mepath ne "./");
#dbx print STDERR "INC: ".join(" ",@INC) . "\n";

my  $arg    = "";
my  @argv   = ();   # all options, including those from RC-FILE
                    # will be used when ever possible instead of @ARGV
# arrays to collect data for debugging, they are global!
our $warning= 1;    # print warnings; need this variable very early

#| definitions: forward declarations
#| -------------------------------------
sub __SSLinfo($$$);
sub _is_intern($);  # Perl avoid: main::_is_member() called too early to check prototype
sub _is_member($$); #   "

#| README if any
#| -------------------------------------
#if (open(my $rc, '<', "o-saft-README")) { print <$rc>; close($rc); exit 0; };
    # 6/2016: o-saft-README disabled because most people asked how to remove it
    # which is clearly described in o-saft-README itself. People won't read :-(

#| CGI
#| -------------------------------------
my  $cgi  = 0;
if ($me =~/\.cgi$/) {
    # CGI mode is pretty simple: see {yeast,o-saft}.cgi
    #   code removed here! hence it always fails
    die STR_ERROR, "010: CGI mode requires strict settings" if ((grep{/--cgi=?/} @ARGV) <= 0);
    $cgi = 1;
} # CGI
# $me might not be .cgi but called with --cgi-exec option
$cgi = 1 if ((grep{/(?:--cgi|--cgi-?exec)/i} @ARGV) > 0);

#| definitions: debug and tracing
#| -------------------------------------
# functions and variables used very early in main
sub _dprint { my @txt = @_; local $\ = "\n"; print STDERR STR_DBX, join(" ", @txt); return; }
sub _dbx    { my @txt = @_; _dprint(@txt); return; } # alias for _dprint
sub _warn   {
    #? print warning if wanted; SEE Perl:Message Numbers
    # don't print if ($warning <= 0);
    my @txt = @_;
    return if ((grep{/(?:--no.?warn)/i} @ARGV) > 0);  # ugly hack 'cause we won't pass $warning
    local $\ = "\n";
    print(STR_WARN, join(" ", @txt));
    # TODO: in CGI mode warning must be avoided until HTTP header written
    _yeast_EXIT("exit=WARN - exit on first warning");
    return;
} # _warn

sub _warn_and_exit      {
    #? print warning that --experimental option is required
    #-method:  name of function where this message is called
    #-command: name of command subject to this message
    my @txt = @_;
    local $\ = "\n";
    if ((grep{/(?:--experimental)/i} @ARGV) > 0) {
        my $method = shift;
        _trace("_warn_and_exit $method: " . join(" ", @txt));
    } else {
        printf(STR_WARN . "099: (%s) --experimental option required to use '%s' functionality. Please send us your feedback about this functionality to o-saft(at)lists.owasp.org\n", @txt);
        exit(1);
    }
    return;
} # _warn_and_exit

sub _hint   {
    #? print hint message if wanted
    # don't print if --no-hint given
    my @txt = @_;
    return if ((grep{/(?:--no.?hint)/i} @ARGV) > 0);
    local $\ = "\n"; print(STR_HINT, join(" ", @txt));
    return;
} # _hint

sub _warn_nosni         {
    #? print warning and hint message if no SNI is supported
    my $err = shift;
    my $ssl = shift;
    my $sni = shift;
    return if ($sni < 1);
    return if ($ssl !~ m/^SSLv[23]/);
    # SSLv2 has no SNI; SSLv3 has originally no SNI
    _warn("$err $ssl does not support SNI; related checks skipped");
    _hint("use '--no-sni' for checking");
    return;
} # _warn_nosni

sub _print_read($$)     { my @txt = @_; printf("=== reading: %s (%s) ===\n", @txt) if ((grep{/(?:--no.?header|--cgi)/i} @ARGV) <= 0); return; }
    # print information what will be read
        # $cgi not available, hence we use @ARGV (may contain --cgi or --cgi-exec)
        # $cfg{'out_header'} not yet properly set, see LIMITATIONS also

sub _load_file          {
    # load file with Perl's require using the paths in @INC
    # use `$0 +version --v'  to see which files are loaded
    my $fil = shift;
    my $txt = shift;
    my $err = "";
    #{
    # # currently (2017) disabled, until all modules can be included with require
    #    no warnings qw(once);
    #    return "" if (defined($osaft_standalone)); # SEE Note:Stand-alone
    #}
    # need eval to catch "Can't locate ... in @INC ..."
    eval {require $fil;} or _warn("101: 'require $fil' failed");
    $err = $@;
    chomp $err;
    if ($err eq "") {
        $txt = "$txt done";
        $INC{$fil} = "." . $INC{$fil} if ("/$fil" eq $INC{$fil}); # fix ugly %INC
        # FIXME: above fix fails for NET::SSL* and absolute path like --trace=/file
        $fil = $INC{$fil};
    } else {
        $txt = "$txt failed";
    }
    push(@{$dbx{file}}, $fil);
    _print_read($fil, $txt);
    return $err;
} # _load_file

#| read RC-FILE if any
#| -------------------------------------
_yeast_TIME("cfg{");
_yeast_EXIT("exit=CONF0 - RC-FILE start");
if ((grep{/(?:--rc)$/i} @ARGV) > 0) {           # (re-)compute default RC-File
    $cfg{'RC-FILE'} =  $0;                      # from directory where $0 found
    $cfg{'RC-FILE'} =~ s#($cfg{'me'})$#.$1#;
}
if ((grep{/(?:--rc=)/i} @ARGV) > 0) {           # other RC-FILE given
    $cfg{'RC-FILE'} =  (grep{/--rc=.*/} @ARGV)[0];  # get value --rc=*
    $cfg{'RC-FILE'} =~ s#--rc=##;               # stripp off --rc=
    # no check if file exists, will be done below
}
print "#o-saft.pl  RC-FILE: $cfg{'RC-FILE'}\n" if ((grep{/--v/i} @ARGV) > 0);
my @rc_argv = "";
if ((grep{/(?:--no.?rc)$/i} @ARGV) <= 0) {      # only if not inhibited
    # we do not use a function for following to avoid passing @argv, @rc_argv
    if (open(my $rc, '<:encoding(UTF-8)', "$cfg{'RC-FILE'}")) {
        push(@{$dbx{file}}, $cfg{'RC-FILE'});
        _print_read(  "$cfg{'RC-FILE'}", "RC-FILE done");
        ## no critic qw(ControlStructures::ProhibitMutatingListFunctions)
        #  NOTE: the purpose here is to *change the source array"
        @rc_argv = grep{!/\s*#[^\r\n]*/} <$rc>; # remove comment lines
        @rc_argv = grep{s/[\r\n]//} @rc_argv;   # remove newlines
        @rc_argv = grep{s/\s*([+-]-?)/$1/} @rc_argv;# get options and commands, remove leading spaces
        ## use critic
        close($rc);
        _warn("052: option with trailing spaces '$_'") foreach (grep{m/\s+$/} @rc_argv);
        push(@argv, @rc_argv);
        print "#o-saft.pl  $cfg{'RC-FILE'}: #{" . join("\n  ", "", @rc_argv) .  "\n#}\n" if ((grep{/--v/i} @ARGV) > 0);
    } else {
        _print_read("$cfg{'RC-FILE'}", "RC-FILE: $!") if ((grep{/--v/i} @ARGV) > 0);
    }
}
_yeast_EXIT("exit=CONF1 - RC-FILE end");
$cfg{'RC-ARGV'} = [@rc_argv];

%{$cfg{'done'}} = (             # internal administration
        'hosts'     => 0,
        'dbxfile'   => 0,
        'rc-file'   => 0,
        'init_all'  => 0,
        'ssl_failed'=> 0,       # local counter for SSL connection errors
        'ssl_errors'=> 0,       # total counter for SSL connection errors
        'arg_cmds'  => [],      # contains all commands given as argument
         # all following need to be reset for each host, which is done in
         # _resetchecks()  by matching the key against ^check or ^cipher
        'default_get'   => 0,
        'ciphers_all'   => 0,
        'ciphers_get'   => 0,
        'checkciphers'  => 0,   # not used, as it's called multiple times
        'checkprefered' => 0,
        'check02102'=> 0,
        'check03116'=> 0,
        'check2818' => 0,
        'check6125' => 0,
        'check7525' => 0,
        'checkdates'=> 0,
        'checksizes'=> 0,
        'checkbleed'=> 0,
        'checkcert' => 0,
        'checkprot' => 0,
        'checkdest' => 0,
        'checkhttp' => 0,
        'checksni'  => 0,
        'checkssl'  => 0,
        'checkalpn' => 0,
        'checkdv'   => 0,
        'checkev'   => 0,
        'check_dh'  => 0,
        'check_url' => 0,       # not used, as it's called multiple times
        'check_certchars' => 0,
);

push(@argv, @ARGV); # got all now
push(@ARGV, "--no-header") if ((grep{/--no-?header/} @argv)); # if defined in RC-FILE, needed in _warn()

#| read DEBUG-FILE, if any (source for trace and verbose)
#| -------------------------------------
my $err = "";
my @dbx = grep{/--(?:trace|v$|yeast)/} @argv;   # may have --trace=./file
if (($#dbx >= 0) and (grep{/--cgi=?/} @argv) <= 0) {
    $arg =  "o-saft-dbx.pm";
    $arg =  $dbx[0] if ($dbx[0] =~ m#/#);
    $arg =~ s#[^=]+=##; # --trace=./myfile.pl
    $err = _load_file($arg, "trace file");
    if ($err ne "") {
        die STR_ERROR, "003: $err" unless (-e $arg);
        # no need to continue if file with debug functions does not exist
        # NOTE: if $mepath or $0 is a symbolic link, above checks fail
        #       we don't fix that! Workaround: install file in ./
    }
} else {
    # debug functions are defined in o-saft-dbx.pm and loaded on demand
    # they must be defined always as they are used wheter requested or not
    sub _yeast_init   {}
    sub _yeast_exit   {}
    sub _yeast_args   {}
    sub _yeast_data   {}
    sub _yeast_ciphers{}
    sub _yeast        {}
    sub _y_ARG        {}
    sub _y_CMD        {}
    sub _v_print      {}
    sub _v2print      {}
    sub _v3print      {}
    sub _v4print      {}
    sub _vprintme     {}
    sub _trace        {}
    sub _trace1       {}
    sub _trace2       {}
    sub _trace3       {}
    sub _trace_cmd    {}
}

#| read USER-FILE, if any (source with user-specified code)
#| -------------------------------------
if ((grep{/--(?:use?r)/} @argv) > 0) { # must have any --usr option
    $err = _load_file("o-saft-usr.pm", "user file");
    if ($err ne "") {
        # continue without warning, it's already printed in "=== reading: " line
        sub usr_version     { return ""; }; # dummy stub, see o-saft-usr.pm
        sub usr_pre_init    {}; #  "
        sub usr_pre_file    {}; #  "
        sub usr_pre_args    {}; #  "
        sub usr_pre_exec    {}; #  "
        sub usr_pre_cipher  {}; #  "
        sub usr_pre_main    {}; #  "
        sub usr_pre_host    {}; #  "
        sub usr_pre_info    {}; #  "
        sub usr_pre_open    {}; #  "
        sub usr_pre_cmds    {}; #  "
        sub usr_pre_data    {}; #  "
        sub usr_pre_print   {}; #  "
        sub usr_pre_next    {}; #  "
        sub usr_pre_exit    {}; #  "
    }
}

usr_pre_init();

#| initialize defaults
#| -------------------------------------
#!# set defaults
#!# -------------------------------------
#!# To make (programmer's) life simple, we try to avoid complex data structure,
#!# which are error-prone, by using a couple of global variables.
#!# As there are no plans to run this tool in threaded mode, this should be ok.
#!# Please see "Program Code" in o-saft-man.pm too.
#!#
#!# Here's an overview of the used global variables (mostly defined in o-saft-lib.pm):
#!#   $me             - the program name or script name with path stripped off
#!#   %prot           - collected data per protocol (from Net::SSLinfo)
#!#   %prot_txt       - labes for %prot
#!#   @cipher_results - where we store the results as:  [SSL, cipher, "yes|no"]
#!#   %data           - labels and correspondig value (from Net::SSLinfo)
#!#   %checks         - collected and checked certificate data
#!#                     collected and checked target (connection) data
#!#                     collected and checked connection data
#!#                     collected and checked length and count data
#!#                     HTTP vs. HTTPS checks
#!#   %shorttexts     - same as %checks, but short texts
#!#   %data_oid       - map known OIDs to human readable description
#!#   %info           - like $data, but for data not retrived from Net::SSLinfo
#!#   %cmd            - configuration for external commands
#!#   %cfg            - configuration for commands and options herein
#!#   %text           - configuration for message texts
#!#   %scores         - scoring values
#!#   %ciphers_desc   - description of %ciphers data structure
#!#   %ciphers        - our ciphers
#!#   %cipher_names   - (hash)map of cipher constant-names to names
#!#   %cipher_alias   - (hash)map of cipher aliases (used in other programs)
#!#
#!# All %check_*  contain a default 'score' value of 10, see --cfg-score
#!# option how to change that.

# NOTE: all keys in data and check_* must be unique 'cause of shorttexts!!
# NOTE: all keys in check_* and checks  must be in lower case letters!!
#       'cause generic conversion of +commands to keys
#       exception are the keys related to protocol, i.e. SSLV3, TLSv11

#
# Note according perlish programming style:
#     references to $arr->{'val') are most often simplified as $arr->{val)
#     same applies to 'txt', 'typ' and 'score'

# some temporary variables used in main
my $host    = "";   # the host currently processed in main
my $port    = "";   # the port currently used in main
my $legacy  = "";   # the legacy mode used in main
my $verbose = 0;    # verbose mode used in main
   # above host, port, legacy and verbose are just shortcuts for corresponding
   # values in $cfg{}, used for better human readability
my $info    = 0;    # set to 1 if +info
my $check   = 0;    # set to 1 if +check was used
my $quick   = 0;    # set to 1 if +quick was used
my $cmdsni  = 0;    # set to 1 if +sni  or +sni_check was used

our %info   = (     # same as %data with values only; keys are identical to %data
    'alpn'          => "",
    'npn'           => "",
    'alpns'         => "",
    'npns'          => "",
);

our %data0  = ();   # same as %data but has 'val' only, no 'txt'
                    # contains values from first connection only

    # NOTE do not change names of keys in %data and all %check_* as these keys
    #      are used in output with --trace-key
our %data   = (     # connection and certificate details
    # values from Net::SSLinfo, will be processed in print_data()
    #!#----------------+-----------------------------------------------------------+-----------------------------------
    #!# +command                 value from Net::SSLinfo::*()                                label to be printed
    #!#----------------+-----------------------------------------------------------+-----------------------------------
    'cn_nosni'      => {'val' => "",                                                'txt' => "Certificate CN without SNI"},
    'pem'           => {'val' => sub { Net::SSLinfo::pem(           $_[0], $_[1])}, 'txt' => "Certificate PEM"},
    'text'          => {'val' => sub { Net::SSLinfo::text(          $_[0], $_[1])}, 'txt' => "Certificate PEM decoded"},
    'cn'            => {'val' => sub { Net::SSLinfo::cn(            $_[0], $_[1])}, 'txt' => "Certificate Common Name"},
    'subject'       => {'val' => sub { Net::SSLinfo::subject(       $_[0], $_[1])}, 'txt' => "Certificate Subject"},
    'issuer'        => {'val' => sub { Net::SSLinfo::issuer(        $_[0], $_[1])}, 'txt' => "Certificate Issuer"},
    'altname'       => {'val' => sub { Net::SSLinfo::altname(       $_[0], $_[1])}, 'txt' => "Certificate Subject's Alternate Names"},
    'cipher_selected'=>{'val' => sub { Net::SSLinfo::selected(      $_[0], $_[1])}, 'txt' => "Selected Cipher"},  # SEE Note:Selected Cipher
    'ciphers_local' => {'val' => sub { Net::SSLinfo::cipher_openssl()},             'txt' => "Local SSLlib Ciphers"},
    'ciphers'       => {'val' => sub { join(" ",  Net::SSLinfo::ciphers($_[0], $_[1]))}, 'txt' => "Client Ciphers"},
    'dates'         => {'val' => sub { join(" .. ", Net::SSLinfo::dates($_[0], $_[1]))}, 'txt' => "Certificate Validity (date)"},
    'before'        => {'val' => sub { Net::SSLinfo::before(        $_[0], $_[1])}, 'txt' => "Certificate valid since"},
    'after'         => {'val' => sub { Net::SSLinfo::after(         $_[0], $_[1])}, 'txt' => "Certificate valid until"},
    'aux'           => {'val' => sub { Net::SSLinfo::aux(           $_[0], $_[1])}, 'txt' => "Certificate Trust Information"},
    'email'         => {'val' => sub { Net::SSLinfo::email(         $_[0], $_[1])}, 'txt' => "Certificate Email Addresses"},
    'pubkey'        => {'val' => sub { Net::SSLinfo::pubkey(        $_[0], $_[1])}, 'txt' => "Certificate Public Key"},
    'pubkey_algorithm'=>{'val'=> sub { Net::SSLinfo::pubkey_algorithm($_[0],$_[1])},'txt' => "Certificate Public Key Algorithm"},
    'pubkey_value'  => {'val' => sub {    __SSLinfo('pubkey_value', $_[0], $_[1])}, 'txt' => "Certificate Public Key Value"},
    'modulus_len'   => {'val' => sub { Net::SSLinfo::modulus_len(   $_[0], $_[1])}, 'txt' => "Certificate Public Key Length"},
    'modulus'       => {'val' => sub { Net::SSLinfo::modulus(       $_[0], $_[1])}, 'txt' => "Certificate Public Key Modulus"},
    'modulus_exponent'=>{'val'=> sub { Net::SSLinfo::modulus_exponent($_[0],$_[1])},'txt' => "Certificate Public Key Exponent"},
    'serial'        => {'val' => sub { Net::SSLinfo::serial(        $_[0], $_[1])}, 'txt' => "Certificate Serial Number"},
    'serial_hex'    => {'val' => sub { Net::SSLinfo::serial_hex(    $_[0], $_[1])}, 'txt' => "Certificate Serial Number (hex)"},
    'serial_int'    => {'val' => sub { Net::SSLinfo::serial_int(    $_[0], $_[1])}, 'txt' => "Certificate Serial Number (int)"},
    'certversion'   => {'val' => sub { Net::SSLinfo::version(       $_[0], $_[1])}, 'txt' => "Certificate Version"},
    'sigdump'       => {'val' => sub { Net::SSLinfo::sigdump(       $_[0], $_[1])}, 'txt' => "Certificate Signature (hexdump)"},
    'sigkey_len'    => {'val' => sub { Net::SSLinfo::sigkey_len(    $_[0], $_[1])}, 'txt' => "Certificate Signature Key Length"},
    'signame'       => {'val' => sub { Net::SSLinfo::signame(       $_[0], $_[1])}, 'txt' => "Certificate Signature Algorithm"},
    'sigkey_value'  => {'val' => sub {    __SSLinfo('sigkey_value', $_[0], $_[1])}, 'txt' => "Certificate Signature Key Value"},
    'trustout'      => {'val' => sub { Net::SSLinfo::trustout(      $_[0], $_[1])}, 'txt' => "Certificate trusted"},
    'extensions'    => {'val' => sub { __SSLinfo('extensions',      $_[0], $_[1])}, 'txt' => "Certificate extensions"},
    'tlsextdebug'   => {'val' => sub { __SSLinfo('tlsextdebug',     $_[0], $_[1])}, 'txt' => "TLS extensions (debug)"},
    'tlsextensions' => {'val' => sub { __SSLinfo('tlsextensions',   $_[0], $_[1])}, 'txt' => "TLS extensions"},
    'ext_authority' => {'val' => sub { __SSLinfo('ext_authority',   $_[0], $_[1])}, 'txt' => "Certificate extensions Authority Information Access"},
    'ext_authorityid'=>{'val' => sub { __SSLinfo('ext_authorityid', $_[0], $_[1])}, 'txt' => "Certificate extensions Authority key Identifier"},
    'ext_constraints'=>{'val' => sub { __SSLinfo('ext_constraints', $_[0], $_[1])}, 'txt' => "Certificate extensions Basic Constraints"},
    'ext_cps'       => {'val' => sub { __SSLinfo('ext_cps',         $_[0], $_[1])}, 'txt' => "Certificate extensions Certificate Policies"},
    'ext_cps_cps'   => {'val' => sub { __SSLinfo('ext_cps_cps',     $_[0], $_[1])}, 'txt' => "Certificate extensions Certificate Policies: CPS"},
    'ext_cps_policy'=> {'val' => sub { __SSLinfo('ext_cps_policy',  $_[0], $_[1])}, 'txt' => "Certificate extensions Certificate Policies: Policy"},
    'ext_cps_notice'=> {'val' => sub { __SSLinfo('ext_cps_notice',  $_[0], $_[1])}, 'txt' => "Certificate extensions Certificate Policies: User Notice"},
    'ext_crl'       => {'val' => sub { __SSLinfo('ext_crl',         $_[0], $_[1])}, 'txt' => "Certificate extensions CRL Distribution Points"},
    'ext_subjectkeyid'=>{'val'=> sub { __SSLinfo('ext_subjectkeyid',$_[0], $_[1])}, 'txt' => "Certificate extensions Subject Key Identifier"},
    'ext_keyusage'  => {'val' => sub { __SSLinfo('ext_keyusage',    $_[0], $_[1])}, 'txt' => "Certificate extensions Key Usage"},
    'ext_extkeyusage'=>{'val' => sub { __SSLinfo('ext_extkeyusage', $_[0], $_[1])}, 'txt' => "Certificate extensions Extended Key Usage"},
    'ext_certtype'  => {'val' => sub { __SSLinfo('ext_certtype',    $_[0], $_[1])}, 'txt' => "Certificate extensions Netscape Cert Type"},
    'ext_issuer'    => {'val' => sub { __SSLinfo('ext_issuer',      $_[0], $_[1])}, 'txt' => "Certificate extensions Issuer Alternative Name"},
    'ocsp_uri'      => {'val' => sub { Net::SSLinfo::ocsp_uri(      $_[0], $_[1])}, 'txt' => "Certificate OCSP Responder URL"},
    'ocspid'        => {'val' => sub {       __SSLinfo('ocspid',    $_[0], $_[1])}, 'txt' => "Certificate OCSP Hashes"},
    'ocsp_subject_hash'   => {'val' => sub { __SSLinfo('ocsp_subject_hash', $_[0], $_[1])}, 'txt' => "Certificate OCSP Subject Hash"},
    'ocsp_public_hash'    => {'val' => sub { __SSLinfo('ocsp_public_hash',  $_[0], $_[1])}, 'txt' => "Certificate OCSP Public Key Hash"},
    'subject_hash'  => {'val' => sub { Net::SSLinfo::subject_hash(  $_[0], $_[1])}, 'txt' => "Certificate Subject Name Hash"},
    'issuer_hash'   => {'val' => sub { Net::SSLinfo::issuer_hash(   $_[0], $_[1])}, 'txt' => "Certificate Issuer Name Hash"},
    'selfsigned'    => {'val' => sub { Net::SSLinfo::selfsigned(    $_[0], $_[1])}, 'txt' => "Certificate Validity (signature)"},
    'fingerprint_type'=>{'val'=> sub { Net::SSLinfo::fingerprint_type($_[0],$_[1])},'txt' => "Certificate Fingerprint Algorithm"},
    'fingerprint_hash'=>{'val'=> sub { __SSLinfo('fingerprint_hash',$_[0], $_[1])}, 'txt' => "Certificate Fingerprint Hash Value"},
    'fingerprint_sha2'=>{'val'=> sub { __SSLinfo('fingerprint_sha2',$_[0], $_[1])}, 'txt' => "Certificate Fingerprint SHA2"},
    'fingerprint_sha1'=>{'val'=> sub { __SSLinfo('fingerprint_sha1',$_[0], $_[1])}, 'txt' => "Certificate Fingerprint SHA1"},
    'fingerprint_md5' =>{'val'=> sub { __SSLinfo('fingerprint_md5', $_[0], $_[1])}, 'txt' => "Certificate Fingerprint  MD5"},
    'fingerprint'   => {'val' => sub { __SSLinfo('fingerprint',     $_[0], $_[1])}, 'txt' => "Certificate Fingerprint"},
    'cert_type'     => {'val' => sub { Net::SSLinfo::cert_type(     $_[0], $_[1])}, 'txt' => "Certificate Type (bitmask)"},
    'sslversion'    => {'val' => sub { Net::SSLinfo::SSLversion(    $_[0], $_[1])}, 'txt' => "Selected SSL Protocol"},
    'resumption'    => {'val' => sub { Net::SSLinfo::resumption(    $_[0], $_[1])}, 'txt' => "Target supports Resumption"},
    'renegotiation' => {'val' => sub { Net::SSLinfo::renegotiation( $_[0], $_[1])}, 'txt' => "Target supports Renegotiation"},
    'compression'   => {'val' => sub { Net::SSLinfo::compression(   $_[0], $_[1])}, 'txt' => "Target supports Compression"},
    'expansion'     => {'val' => sub { Net::SSLinfo::expansion(     $_[0], $_[1])}, 'txt' => "Target supports Expansion"},
    'krb5'          => {'val' => sub { Net::SSLinfo::krb5(          $_[0], $_[1])}, 'txt' => "Target supports Krb5"},
    'psk_hint'      => {'val' => sub { Net::SSLinfo::psk_hint(      $_[0], $_[1])}, 'txt' => "Target supports PSK Identity Hint"},
    'psk_identity'  => {'val' => sub { Net::SSLinfo::psk_identity(  $_[0], $_[1])}, 'txt' => "Target supports PSK"},
    'srp'           => {'val' => sub { Net::SSLinfo::srp(           $_[0], $_[1])}, 'txt' => "Target supports SRP"},
    'heartbeat'     => {'val' => sub {    __SSLinfo('heartbeat',    $_[0], $_[1])}, 'txt' => "Target supports Heartbeat"},
    'next_protocols'=> {'val' => sub { Net::SSLinfo::next_protocols($_[0], $_[1])}, 'txt' => "Target's advertised protocols"},
#   'alpn'          => {'val' => sub { Net::SSLinfo::alpn(          $_[0], $_[1])}, 'txt' => "Target's selected protocol (ALPN)"}, # old, pre 17.04.17 version
    'alpn'          => {'val' => sub { return $info{'alpn'};                     }, 'txt' => "Target's selected protocol (ALPN)"},
    'npn'           => {'val' => sub { return $info{'npn'};                      }, 'txt' => "Target's selected protocol  (NPN)"},
    'alpns'         => {'val' => sub { return $info{'alpns'};                    }, 'txt' => "Target's supported ALPNs"},
    'npns'          => {'val' => sub { return $info{'npns'};                     }, 'txt' => "Target's supported  NPNs"},
    'master_key'    => {'val' => sub { Net::SSLinfo::master_key(    $_[0], $_[1])}, 'txt' => "Target's Master-Key"},
    'session_id'    => {'val' => sub { Net::SSLinfo::session_id(    $_[0], $_[1])}, 'txt' => "Target's Session-ID"},
    'session_protocol'=>{'val'=> sub { Net::SSLinfo::session_protocol($_[0],$_[1])},'txt' => "Target's selected SSL Protocol"},
    'session_ticket'=> {'val' => sub { Net::SSLinfo::session_ticket($_[0], $_[1])}, 'txt' => "Target's TLS Session Ticket"},
    'session_lifetime'=>{'val'=> sub { Net::SSLinfo::session_lifetime($_[0],$_[1])},'txt' => "Target's TLS Session Ticket Lifetime"},
    'session_timeout'=>{'val' => sub { Net::SSLinfo::session_timeout($_[0],$_[1])}, 'txt' => "Target's TLS Session Timeout"},
    'dh_parameter'  => {'val' => sub { Net::SSLinfo::dh_parameter(  $_[0], $_[1])}, 'txt' => "Target's DH Parameter"},
    'chain'         => {'val' => sub { Net::SSLinfo::chain(         $_[0], $_[1])}, 'txt' => "Certificate Chain"},
    'chain_verify'  => {'val' => sub { Net::SSLinfo::chain_verify(  $_[0], $_[1])}, 'txt' => "CA Chain Verification (trace)"},
    'verify'        => {'val' => sub { Net::SSLinfo::verify(        $_[0], $_[1])}, 'txt' => "Validity Certificate Chain"},
    'error_verify'  => {'val' => sub { Net::SSLinfo::error_verify(  $_[0], $_[1])}, 'txt' => "CA Chain Verification error"},
    'error_depth'   => {'val' => sub { Net::SSLinfo::error_depth(   $_[0], $_[1])}, 'txt' => "CA Chain Verification error in level"},
    'verify_altname'=> {'val' => sub { Net::SSLinfo::verify_altname($_[0], $_[1])}, 'txt' => "Validity Alternate Names"},
    'verify_hostname'=>{'val' => sub { Net::SSLinfo::verify_hostname( $_[0],$_[1])},'txt' => "Validity Hostname"},
    'https_protocols'=>{'val' => sub { Net::SSLinfo::https_protocols($_[0],$_[1])}, 'txt' => "HTTPS Alternate-Protocol"},
    'https_svc'     => {'val' => sub { Net::SSLinfo::https_svc(     $_[0], $_[1])}, 'txt' => "HTTPS Alt-Svc header"},
    'https_status'  => {'val' => sub { Net::SSLinfo::https_status(  $_[0], $_[1])}, 'txt' => "HTTPS Status line"},
    'https_server'  => {'val' => sub { Net::SSLinfo::https_server(  $_[0], $_[1])}, 'txt' => "HTTPS Server banner"},
    'https_location'=> {'val' => sub { Net::SSLinfo::https_location($_[0], $_[1])}, 'txt' => "HTTPS Location header"},
    'https_refresh' => {'val' => sub { Net::SSLinfo::https_refresh( $_[0], $_[1])}, 'txt' => "HTTPS Refresh header"},
    'https_alerts'  => {'val' => sub { Net::SSLinfo::https_alerts(  $_[0], $_[1])}, 'txt' => "HTTPS Error alerts"},
    'https_pins'    => {'val' => sub { Net::SSLinfo::https_pins(    $_[0], $_[1])}, 'txt' => "HTTPS Public Key Pins"},
    'https_body'    => {'val' => sub { Net::SSLinfo::https_body(    $_[0], $_[1])}, 'txt' => "HTTPS Body"},
    'https_sts'     => {'val' => sub { Net::SSLinfo::https_sts(     $_[0], $_[1])}, 'txt' => "HTTPS STS header"},
    'hsts_httpequiv'=> {'val' => sub { Net::SSLinfo::hsts_httpequiv($_[0], $_[1])}, 'txt' => "HTTPS STS in http-equiv"},
    'hsts_maxage'   => {'val' => sub { Net::SSLinfo::hsts_maxage(   $_[0], $_[1])}, 'txt' => "HTTPS STS MaxAge"},
    'hsts_subdom'   => {'val' => sub { Net::SSLinfo::hsts_subdom(   $_[0], $_[1])}, 'txt' => "HTTPS STS include sub-domains"},
    'hsts_preload'  => {'val' => sub { Net::SSLinfo::hsts_preload(  $_[0], $_[1])}, 'txt' => "HTTPS STS preload"},
    'http_protocols'=> {'val' => sub { Net::SSLinfo::http_protocols($_[0], $_[1])}, 'txt' => "HTTP Alternate-Protocol"},
    'http_svc'      => {'val' => sub { Net::SSLinfo::http_svc(      $_[0], $_[1])}, 'txt' => "HTTP Alt-Svc header"},
    'http_status'   => {'val' => sub { Net::SSLinfo::http_status(   $_[0], $_[1])}, 'txt' => "HTTP Status line"},
    'http_location' => {'val' => sub { Net::SSLinfo::http_location( $_[0], $_[1])}, 'txt' => "HTTP Location header"},
    'http_refresh'  => {'val' => sub { Net::SSLinfo::http_refresh(  $_[0], $_[1])}, 'txt' => "HTTP Refresh header"},
    'http_sts'      => {'val' => sub { Net::SSLinfo::http_sts(      $_[0], $_[1])}, 'txt' => "HTTP STS header"},
    #------------------+---------------------------------------+-------------------------------------------------------
    'options'       => {'val' => sub { Net::SSLinfo::options(       $_[0], $_[1])}, 'txt' => "<<internal>> used SSL options bitmask"},
    'fallback_protocol' => {'val' => sub { return $prot{'fallback'}->{val}       }, 'txt' => "Target's fallback SSL Protocol"},
    #------------------+---------------------------------------+-------------------------------------------------------
    # following not printed by default, but can be used as command
#   'PROT'          => {'val' => sub { return $prot{'PROT'}->{'default'}         }, 'txt' => "Target default PROT     cipher"}, #####
    # all others will be added below
    #------------------+---------------------------------------+-------------------------------------------------------
    # following are used for checkdates() only, they must not be a command!
    # they are not printed with +info or +check; values are integer
    'valid_years'   => {'val' =>  0, 'txt' => "certificate validity in years"},
    'valid_months'  => {'val' =>  0, 'txt' => "certificate validity in months"},
    'valid_days'    => {'val' =>  0, 'txt' => "certificate validity in days"},  # approx. value, accurate if < 30
    'valid_host'    => {'val' =>  0, 'txt' => "dummy used for printing DNS stuff"},
); # %data
# need s_client for: compression|expansion|selfsigned|chain|verify|resumption|renegotiation|next_protocols|
# need s_client for: krb5|psk_hint|psk_identity|srp|master_key|session_id|session_protocol|session_ticket|session_lifetime|session_timeout

# add keys from %prot to %data,
foreach my $ssl (keys %prot) {
    my $key = lc($ssl); # keys in data are all lowercase (see: convert all +CMD)
    $data{$key}->{val} = sub {    return $prot{$ssl}->{'default'}; };
    $data{$key}->{txt} = "Target default $prot{$ssl}->{txt} cipher";
}

# NOTE: the comments prefixed with  ##  are used by third-party software,
#       for example o-saft.tcl uses a pattern like:
#           (?:my|our) check_(.*)=\( ## (.*)

our %checks = (
    # key           =>  {val => "", txt => "label to be printed", score => 0, typ => "connection"},
    #
    # default for 'val' is "" (empty string), default for 'score' is 0
    # 'typ' is any of certificate, connection, destination, https, sizes
    # both will be set in sub _init_all(), please see below

    # the default value means "check = ok/yes", otherwise: "check =failed/no"

); # %checks

my %check_cert = (  ## certificate data
    # collected and checked certificate data
    #------------------+-----------------------------------------------------
    # key               label to be printed (description)
    #------------------+-----------------------------------------------------
    'verify'        => {'txt' => "Certificate chain validated"},
    'fp_not_md5'    => {'txt' => "Certificate Fingerprint is not MD5"},
    'dates'         => {'txt' => "Certificate is valid"},
    'expired'       => {'txt' => "Certificate is not expired"},
    'certfqdn'      => {'txt' => "Certificate is valid according given hostname"},
    'wildhost'      => {'txt' => "Certificate's wildcard does not match hostname"},
    'wildcard'      => {'txt' => "Certificate does not contain wildcards"},
    'rootcert'      => {'txt' => "Certificate is not root CA"},
    'selfsigned'    => {'txt' => "Certificate is not self-signed"},
    'dv'            => {'txt' => "Certificate Domain Validation (DV)"},
    'ev+'           => {'txt' => "Certificate strict Extended Validation (EV)"},
    'ev-'           => {'txt' => "Certificate lazy Extended Validation (EV)"},
    'ocsp_uri'      => {'txt' => "Certificate has OCSP Responder URL"},
    'cps'           => {'txt' => "Certificate has Certification Practice Statement"},
    'crl'           => {'txt' => "Certificate has CRL Distribution Points"},
    'zlib'          => {'txt' => "Certificate has (TLS extension) compression"},
    'lzo'           => {'txt' => "Certificate has (GnuTLS extension) compression"},
    'open_pgp'      => {'txt' => "Certificate has (TLS extension) authentication"},
    'ocsp_valid'    => {'txt' => "Certificate has valid OCSP URL"},
    'cps_valid'     => {'txt' => "Certificate has valid CPS URL"},
    'crl_valid'     => {'txt' => "Certificate has valid CRL URL"},
    'sernumber'     => {'txt' => "Certificate Serial Number size RFC5280"},
    'constraints'   => {'txt' => "Certificate Basic Constraints is false"},
    'sha2signature' => {'txt' => "Certificate Private Key Signature SHA2"},
    'modulus_exp_1' => {'txt' => "Certificate Public Key Modulus Exponent <>1"},
    'modulus_size_oldssl' => {'txt' => "Certificate Public Key Modulus >16385 bits"},
    'modulus_exp_65537' =>{'txt'=> "Certificate Public Key Modulus Exponent =65537"},
    'modulus_exp_oldssl'=>{'txt'=> "Certificate Public Key Modulus Exponent >65537"},
    'pub_encryption'=> {'txt' => "Certificate Public Key with Encryption"},
    'pub_enc_known' => {'txt' => "Certificate Public Key Encryption known"},
    'sig_encryption'=> {'txt' => "Certificate Private Key with Encryption"},
    'sig_enc_known' => {'txt' => "Certificate Private Key Encryption known"},
    'rfc_6125_names'=> {'txt' => "Certificate Names compliant to RFC6125"},
    'rfc_2818_names'=> {'txt' => "Certificate subjectAltNames compliant to RFC2818"},
    # following checks in subjectAltName, CRL, OCSP, CN, O, U
    'nonprint'      => {'txt' => "Certificate does not contain non-printable characters"},
    'crnlnull'      => {'txt' => "Certificate does not contain CR, NL, NULL characters"},
    'ev_chars'      => {'txt' => "Certificate has no invalid characters in extensions"},
# TODO: SRP is a target feature but also named a `Certificate (TLS extension)'
#    'srp'           => {'txt' => "Certificate has (TLS extension) authentication"},
    #------------------+-----------------------------------------------------
    # extensions:
    #   KeyUsage:
    #     0 - digitalSignature
    #     1 - nonRepudiation
    #     2 - keyEncipherment
    #     3 - dataEncipherment
    #     4 - keyAgreement
    #     5 - keyCertSign      # indicates this is CA cert
    #     6 - cRLSign
    #     7 - encipherOnly
    #     8 - decipherOnly
    # verify, is-trusted: certificate must be trusted, not expired (after also)
    #  common name or altname matches given hostname
    #     1 - no chain of trust
    #     2 - not before
    #     4 - not after
    #     8 - hostname mismatch
    #    16 - revoked
    #    32 - bad common name
    #    64 - self-signed
    # possible problems with chains:
    #   - contains untrusted certificate
    #   - chain incomplete/not resolvable
    #   - chain too long (depth)
    #   - chain size too big
    #   - contains illegal characters
    # TODO: wee need an option to specify the the local certificate storage!
); # %check_cert

my %check_conn = (  ## connection data
    # collected and checked connection data
    #------------------+-----------------------------------------------------
    'ip'            => {'txt' => "IP for given hostname "},
    'reversehost'   => {'txt' => "Given hostname is same as reverse resolved hostname"},
    'hostname'      => {'txt' => "Connected hostname matches certificate's subject"},
    'beast'         => {'txt' => "Connection is safe against BEAST attack (any cipher)"},
    'breach'        => {'txt' => "Connection is safe against BREACH attack"},
    'crime'         => {'txt' => "Connection is safe against CRIME attack"},
    'drown'         => {'txt' => "Connection is safe against DROWN attack"},
    'time'          => {'txt' => "Connection is safe against TIME attack"},
    'freak'         => {'txt' => "Connection is safe against FREAK attack"},
    'heartbleed'    => {'txt' => "Connection is safe against Heartbleed attack"},
    'logjam'        => {'txt' => "Connection is safe against Logjam attack"},
    'lucky13'       => {'txt' => "Connection is safe against Lucky 13 attack"},
    'poodle'        => {'txt' => "Connection is safe against POODLE attack"},
    'rc4'           => {'txt' => "Connection is safe against RC4 attack"},
    'robot'         => {'txt' => "Connection is safe against ROBOT attack"},
    'sloth'         => {'txt' => "Connection is safe against SLOTH attack"},
    'sweet32'       => {'txt' => "Connection is safe against Sweet32 attack"},
    'sni'           => {'txt' => "Connection is not based on SNI"},
     # NOTE: following keys use mixed case letters, that's ok 'cause these
     #       checks are not called by their own commands; ugly hack ...
    #------------------+-----------------------------------------------------
); # %check_conn

my %check_dest = (  ## target (connection) data
    # collected and checked target (connection) data
    #------------------+-----------------------------------------------------
    'sgc'           => {'txt' => "Target supports Server Gated Cryptography (SGC)"},
    'hassslv2'      => {'txt' => "Target does not support SSLv2"},
    'hassslv3'      => {'txt' => "Target does not support SSLv3"},      # POODLE
    'hastls10'      => {'txt' => "Target supports TLSv1"},
    'hastls11'      => {'txt' => "Target supports TLSv1.1"},
    'hastls12'      => {'txt' => "Target supports TLSv1.2"},
    'hastls13'      => {'txt' => "Target supports TLSv1.3"},
    'hasalpn'       => {'txt' => "Target supports ALPN"},
    'hasnpn'        => {'txt' => "Target supports  NPN"},
    'cipher_strong' => {'txt' => "Target selects strongest cipher"},
    'cipher_order'  => {'txt' => "Target does not honors client's cipher order"}, # NOT YET USED
    'cipher_weak'   => {'txt' => "Target does not accept weak cipher"},
    'cipher_null'   => {'txt' => "Target does not accept NULL ciphers"},
    'cipher_adh'    => {'txt' => "Target does not accept ADH ciphers"},
    'cipher_exp'    => {'txt' => "Target does not accept EXPORT ciphers"},
    'cipher_cbc'    => {'txt' => "Target does not accept CBC ciphers"},
    'cipher_des'    => {'txt' => "Target does not accept DES ciphers"},
    'cipher_rc4'    => {'txt' => "Target does not accept RC4 ciphers"},
    'cipher_edh'    => {'txt' => "Target supports EDH ciphers"},
    'cipher_pfs'    => {'txt' => "Target supports PFS (selected cipher)"},
    'cipher_pfsall' => {'txt' => "Target supports PFS (all ciphers)"},
    'closure'       => {'txt' => "Target understands TLS closure alerts"},
    'fallback'      => {'txt' => "Target supports fallback from TLSv1.1"},
    'ism'           => {'txt' => "Target is ISM compliant (ciphers only)"},
    'pci'           => {'txt' => "Target is PCI compliant (ciphers only)"},
    'fips'          => {'txt' => "Target is FIPS-140 compliant"},
#   'nsab'          => {'txt' => "Target is NSA Suite B compliant"},
    'tr_02102+'     => {'txt' => "Target is strict TR-02102-2 compliant"},
    'tr_02102-'     => {'txt' => "Target is  lazy  TR-02102-2 compliant"},
    'tr_03116+'     => {'txt' => "Target is strict TR-03116-4 compliant"},
    'tr_03116-'     => {'txt' => "Target is  lazy  TR-03116-4 compliant"},
    'rfc_7525'      => {'txt' => "Target is RFC 7525 compliant"},
    'resumption'    => {'txt' => "Target supports Resumption"},
    'renegotiation' => {'txt' => "Target supports Secure Renegotiation"},
    'krb5'          => {'txt' => "Target supports Krb5"},
    'psk_hint'      => {'txt' => "Target supports PSK Identity Hint"},
    'psk_identity'  => {'txt' => "Target supports PSK"},
    'srp'           => {'txt' => "Target supports SRP"},
    'session_ticket'=> {'txt' => "Target supports TLS Session Ticket"}, # sometimes missing ...
    'session_lifetime'=>{'txt'=> "Target TLS Session Ticket Lifetime"},
    'session_random'=> {'txt' => "Target TLS Session Ticket is random"},
    'heartbeat'     => {'txt' => "Target does not support heartbeat extension"},
    'scsv'          => {'txt' => "Target does not support SCSV"},
    # following for information, checks not useful; see "# check target specials" in checkdest also
#    'master_key'    => {'txt' => "Target supports Master-Key"},
#    'session_id'    => {'txt' => "Target supports Session-ID"},
    'dh_512'        => {'txt' => "Target DH Parameter >= 512 bits"},
    'dh_2048'       => {'txt' => "Target DH Parameter >= 2048 bits"},
    'ecdh_256'      => {'txt' => "Target DH Parameter >= 256 bits (ECDH)"},
    'ecdh_512'      => {'txt' => "Target DH Parameter >= 512 bits (ECDH)"},
    #------------------+-----------------------------------------------------
); # %check_dest

my %check_size = (  ## length and count data
    # collected and checked length and count data
    # counts and sizes are integer values, key mast have prefix (len|cnt)_
    #------------------+-----------------------------------------------------
    'len_pembase64' => {'txt' => "Certificate PEM (base64) size"},  # <(2048/8*6)
    'len_pembinary' => {'txt' => "Certificate PEM (binary) size"},  # < 2048
    'len_subject'   => {'txt' => "Certificate Subject size"},       # <  256
    'len_issuer'    => {'txt' => "Certificate Issuer size"},        # <  256
    'len_cps'       => {'txt' => "Certificate CPS size"},           # <  256
    'len_crl'       => {'txt' => "Certificate CRL size"},           # <  256
    'len_crl_data'  => {'txt' => "Certificate CRL data size"},
    'len_ocsp'      => {'txt' => "Certificate OCSP size"},          # <  256
    'len_oids'      => {'txt' => "Certificate OIDs size"},
    'len_publickey' => {'txt' => "Certificate Public Key size"},    # > 1024
    # \---> same as modulus_len
    'len_sigdump'   => {'txt' => "Certificate Signature Key size"} ,# > 1024
    'len_altname'   => {'txt' => "Certificate Subject Altname size"},
    'len_chain'     => {'txt' => "Certificate Chain size"},         # < 2048
    'len_sernumber' => {'txt' => "Certificate Serial Number size"}, # <=  20 octets
    'cnt_altname'   => {'txt' => "Certificate Subject Altname count"}, # == 0
    'cnt_wildcard'  => {'txt' => "Certificate Wildcards count"},    # == 0
    'cnt_chaindepth'=> {'txt' => "Certificate Chain Depth count"},  # == 1
    'cnt_ciphers'   => {'txt' => "Total number of offered ciphers"},# <> 0
    'cnt_totals'    => {'txt' => "Total number of checked ciphers"},
    'cnt_checks_no' => {'txt' => "Total number of check results 'no'"},
    'cnt_checks_yes'=> {'txt' => "Total number of check results 'yes'"},
    'cnt_exitcode'  => {'txt' => "Total number of insecure checks"},# == 0
    #------------------+-----------------------------------------------------
# TODO: cnt_ciphers, len_chain, cnt_chaindepth
); # %check_size

my %check_http = (  ## HTTP vs. HTTPS data
    # score are absolute values here, they are set to 100 if attribute is found
    # key must have prefix (hsts|sts); see $cfg{'regex'}->{'cmd-http'}
    #------------------+-----------------------------------------------------
    'sts_maxage0d'  => {'txt' => "STS max-age not reset"},           # max-age=0 is bad
    'sts_maxage1d'  => {'txt' => "STS max-age less than one day"},   # weak
    'sts_maxage1m'  => {'txt' => "STS max-age less than one month"}, # low
    'sts_maxage1y'  => {'txt' => "STS max-age less than one year"},  # medium
    'sts_maxagexy'  => {'txt' => "STS max-age more than one year"},  # high
    'sts_maxage18'  => {'txt' => "STS max-age more than 18 weeks"},  #
    'sts_expired'   => {'txt' => "STS max-age < certificate's validity"},
    'hsts_sts'      => {'txt' => "Target sends STS header"},
    'sts_maxage'    => {'txt' => "Target sends STS header with proper max-age"},
    'sts_subdom'    => {'txt' => "Target sends STS header with includeSubdomain"},
    'sts_preload'   => {'txt' => "Target sends STS header with preload"},
    'hsts_is301'    => {'txt' => "Target redirects with status code 301"}, # RFC6797 requirement
    'hsts_is30x'    => {'txt' => "Target redirects not with 30x status code"}, # other than 301, 304
    'hsts_fqdn'     => {'txt' => "Target redirect matches given host"},
    'http_https'    => {'txt' => "Target redirects HTTP to HTTPS"},
    'hsts_location' => {'txt' => "Target sends STS and no Location header"},
    'hsts_refresh'  => {'txt' => "Target sends STS and no Refresh header"},
    'hsts_redirect' => {'txt' => "Target redirects HTTP without STS header"},
    'hsts_samehost' => {'txt' => "Target redirects HTTP to HTTPS same host"},
    'hsts_ip'       => {'txt' => "Target does not send STS header for IP"},
    'hsts_httpequiv'=> {'txt' => "Target does not send STS in meta tag"},
    'pkp_pins'      => {'txt' => "Target sends Public Key Pins header"},
    #------------------+-----------------------------------------------------
); # %check_http

# now construct %checks from %check_* and set 'typ'
foreach my $key (keys %check_conn) { $checks{$key}->{txt} = $check_conn{$key}->{txt}; $checks{$key}->{typ} = 'connection'; }
foreach my $key (keys %check_cert) { $checks{$key}->{txt} = $check_cert{$key}->{txt}; $checks{$key}->{typ} = 'certificate'; }
foreach my $key (keys %check_dest) { $checks{$key}->{txt} = $check_dest{$key}->{txt}; $checks{$key}->{typ} = 'destination'; }
foreach my $key (keys %check_size) { $checks{$key}->{txt} = $check_size{$key}->{txt}; $checks{$key}->{typ} = 'sizes'; }
foreach my $key (keys %check_http) { $checks{$key}->{txt} = $check_http{$key}->{txt}; $checks{$key}->{typ} = 'https'; }
foreach my $key (keys %checks)     { $checks{$key}->{val} = ""; }
# more data added to %checks after defining %cfg, see below

our %shorttexts = (
    #------------------+------------------------------------------------------
    # %check +check     short label text
    #------------------+------------------------------------------------------
    'ip'            => "IP for hostname",
    'DNS'           => "DNS for hostname",
    'reversehost'   => "Reverse hostname",
    'hostname'      => "Hostname matches Subject",
    'expired'       => "Not expired",
    'certfqdn'      => "Valid for hostname",
    'wildhost'      => "Wilcard for hostname",
    'wildcard'      => "No wildcards",
    'sni'           => "Not SNI based",
    'sernumber'     => "Size Serial Number",
    'sha2signature' => "Signature is SHA2",
    'rootcert'      => "Not root CA",
    'ocsp_uri'      => "OCSP URL",
    'ocsp_valid'    => "OCSP valid",
    'hassslv2'      => "No SSLv2",
    'hassslv3'      => "No SSLv3",
    'hastls10'      => "TLSv1",
    'hastls11'      => "TLSv1.1",
    'hastls12'      => "TLSv1.2",
    'hastls13'      => "TLSv1.3",
    'hasalpn'       => "Supports ALPN",
    'hasnpn'        => "Supports  NPN",
    'alpn'          => "Selected ALPN",
    'npn'           => "Selected  NPN",
    'alpns'         => "Supported ALPNs",
    'npns'          => "Supported  NPNs",
    'next_protocols'=> "(NPN) Protocols",
    'cipher_strong' => "Strongest cipher selected",
    'cipher_order'  => "Client's cipher order",
    'cipher_weak'   => "Weak cipher selected",
    'cipher_null'   => "No NULL ciphers",
    'cipher_adh'    => "No ADH ciphers",
    'cipher_exp'    => "No EXPORT ciphers",
    'cipher_cbc'    => "No CBC ciphers",
    'cipher_des'    => "No DES ciphers",
    'cipher_rc4'    => "No RC4 ciphers",
    'cipher_edh'    => "EDH ciphers",
    'cipher_pfs'    => "PFS (selected cipher)",
    'cipher_pfsall' => "PFS (all ciphers)",
    'sgc'           => "SGC supported",
    'cps'           => "CPS supported",
    'crl'           => "CRL supported",
    'cps_valid'     => "CPS valid",
    'crl_valid'     => "CRL valid",
    'dv'            => "DV supported",
    'ev+'           => "EV supported (strict)",
    'ev-'           => "EV supported (lazy)",
    'ev_chars'      => "No invalid characters in extensions",
    'beast'         => "Safe to BEAST (cipher)",
    'breach'        => "Safe to BREACH",
    'crime'         => "Safe to CRIME",
    'drown'         => "Safe to DROWN",
    'time'          => "Safe to TIME",
    'freak'         => "Safe to FREAK",
    'heartbleed'    => "Safe to Heartbleed",
    'lucky13'       => "Safe to Lucky 13",
    'logjam'        => "Safe to Logjam",
    'poodle'        => "Safe to POODLE",
    'rc4'           => "Safe to RC4 attack",
    'robot'         => "Safe to ROBOT",
    'sloth'         => "Safe to SLOTH",
    'sweet32'       => "Safe to Sweet32",
    'scsv'          => "SCSV not supported",
    'constraints'   => "Basic Constraints is false",
    'modulus_exp_1' => "Modulus Exponent <>1",
    'modulus_size_oldssl'  => "Modulus >16385 bits",
    'modulus_exp_65537' =>"Modulus Exponent =65537",
    'modulus_exp_oldssl'=>"Modulus Exponent >65537",
    'pub_encryption'=> "Public Key with Encryption",
    'pub_enc_known' => "Public Key Encryption known",
    'sig_encryption'=> "Private Key with Encryption",
    'sig_enc_known' => "Private Key Encryption known",
    'rfc_6125_names'=> "Names according RFC6125",
    'rfc_2818_names'=> "subjectAltNames according RFC2818",
    'closure'       => "TLS closure alerts",
    'fallback'      => "Fallback from TLSv1.1",
    'zlib'          => "ZLIB extension",
    'lzo'           => "GnuTLS extension",
    'open_pgp'      => "OpenPGP extension",
    'ism'           => "ISM compliant",
    'pci'           => "PCI compliant",
    'fips'          => "FIPS-140 compliant",
#   'nsab'          => "NSA Suite B compliant",
    'tr_02102+'     => "TR-02102-2 compliant (strict)",
    'tr_02102-'     => "TR-02102-2 compliant (lazy)",
    'tr_03116+'     => "TR-03116-4 compliant (strict)",
    'tr_03116-'     => "TR-03116-4 compliant (lazy)",
    'rfc_7525'      => "RFC 7525 compliant",
    'resumption'    => "Resumption",
    'renegotiation' => "Renegotiation",     # NOTE used in %data and %check_dest
    'hsts_sts'      => "STS header",
    'sts_maxage'    => "STS long max-age",
    'sts_maxage0d'  => "STS max-age not reset",
    'sts_maxage1d'  => "STS max-age < 1 day",
    'sts_maxage1m'  => "STS max-age < 1 month",
    'sts_maxage1y'  => "STS max-age < 1 year",
    'sts_maxagexy'  => "STS max-age > 1 year",
    'sts_maxage18'  => "STS max-age > 18 weeks",
    'sts_expired'   => "STS max-age < certificate's validity",
    'sts_subdom'    => "STS includeSubdomain",
    'sts_preload'   => "STS preload",
    'hsts_httpequiv'=> "STS not in meta tag",
    'hsts_ip'       => "STS header not for IP",
    'hsts_location' => "STS and Location header",
    'hsts_refresh'  => "STS and no Refresh header",
    'hsts_redirect' => "STS within redirects",
    'http_https'    => "Redirects HTTP",
    'hsts_fqdn'     => "Redirects to same host",
    'hsts_is301'    => "Redirects with 301",
    'hsts_is30x'    => "Redirects not with 30x",
    'pkp_pins'      => "Public Key Pins",
    'selfsigned'    => "Validity (signature)",
    'chain'         => "Certificate chain",
    'chain_verify'  => "CA Chain trace",
    'verify'        => "Chain verified",
    'error_verify'  => "CA Chain error",
    'error_depth'   => "CA Chain error in level",
    'nonprint'      => "No non-printables",
    'crnlnull'      => "No CR, NL, NULL",
    'compression'   => "Compression",
    'expansion'     => "Expansion",
    'krb5'          => "Krb5 Principal",
    'psk_hint'      => "PSK Identity Hint",
    'psk_identity'  => "PSK Identity",
    'srp'           => "SRP Username",
    'master_key'    => "Master-Key",
    'session_id'    => "Session-ID",
    'session_protocol'  => "Selected SSL Protocol",
    'session_ticket'    => "TLS Session Ticket",
    'session_lifetime'  => "TLS Session Ticket Lifetime",
    'session_random'    => "TLS Session Ticket random",
    'session_timeout'   => "TLS Session Timeout",
    'dh_parameter'  => "DH Parameter",
    'dh_512'        => "DH Parameter >= 512",
    'dh_2048'       => "DH Parameter >= 2048",
    'ecdh_256'      => "DH Parameter >= 256 (ECDH)",
    'ecdh_512'      => "DH Parameter >= 512 (ECDH)",
    'ext_authority' => "Authority Information Access",
    'ext_authorityid'=>"Authority key Identifier",
    'ext_constraints'=>"Basic Constraints",
    'ext_cps'       => "Certificate Policies",
    'ext_cps_cps'   => "Certificate Policies: CPS",
    'ext_cps_policy'=> "Certificate Policies: Policy",
    'ext_cps_notice'=> "Certificate Policies: User Notice",
    'ext_crl'       => "CRL Distribution Points",
    'ext_subjectkeyid'=>"Subject Key Identifier",
    'ext_keyusage'  => "Key Usage",
    'ext_extkeyusage'=>"Extended Key Usage",
    'ext_certtype'  => "Netscape Cert Type",
    'ext_issuer'    => "Issuer Alternative Name",
    'fallback_protocol' => "Fallback SSL Protocol",
    'len_pembase64' => "Size PEM (base64)",
    'len_pembinary' => "Size PEM (binary)",
    'len_subject'   => "Size subject",
    'len_issuer'    => "Size issuer",
    'len_cps'       => "Size CPS",
    'len_crl'       => "Size CRL",
    'len_crl_data'  => "Size CRL data",
    'len_ocsp'      => "Size OCSP",
    'len_oids'      => "Size OIDs",
    'len_altname'   => "Size altname",
    'len_publickey' => "Size pubkey",
    'len_sigdump'   => "Size signature key",
    'len_chain'     => "Size certificate chain",
    'len_sernumber' => "Size serial number",
    'cnt_altname'   => "Count altname",
    'cnt_wildcard'  => "Count wildcards",
    'cnt_chaindepth'=> "Count chain depth",
    'cnt_ciphers'   => "Count ciphers",
    'cnt_totals'    => "Checked ciphers",
    'cnt_checks_no' => "Checks 'no'",
    'cnt_checks_yes'=> "Checks 'yes'",
    #------------------+------------------------------------------------------
    # %data +command    short label text
    #------------------+------------------------------------------------------
    'pem'           => "PEM",
    'text'          => "PEM decoded",
    'cn'            => "Common Name",
    'subject'       => "Subject",
    'issuer'        => "Issuer",
    'altname'       => "Subject AltNames",
    'ciphers'       => "Client Ciphers",
    'ciphers_local' => "SSLlib Ciphers",
    'cipher_selected'   => "Selected Cipher",
    'dates'         => "Validity (date)",
    'before'        => "Valid since",
    'after'         => "Valid until",
    'tlsextdebug'   => "TLS Extensions (debug)",
    'tlsextensions' => "TLS Extensions",
    'extensions'    => "Extensions",
    'heartbeat'     => "Heartbeat",     # not realy a `key', but a extension
    'aux'           => "Trust",
    'email'         => "Email",
    'pubkey'        => "Public Key",
    'pubkey_algorithm'  => "Public Key Algorithm",
    'pubkey_value'  => "Public Key Value",
    'modulus_len'   => "Public Key Length",
    'modulus'       => "Public Key Modulus",
    'modulus_exponent'  => "Public Key Exponent",
    'serial'        => "Serial Number",
    'serial_hex'    => "Serial Number (hex)",
    'serial_int'    => "Serial Number (int)",
    'certversion'   => "Certificate Version",
    'sslversion'    => "SSL Protocol",
    'signame'       => "Signature Algorithm",
    'sigdump'       => "Signature (hexdump)",
    'sigkey_len'    => "Signature Key Length",
    'sigkey_value'  => "Signature Key Value",
    'trustout'      => "Trusted",
    'ocspid'        => "OCSP Hashes",
    'ocsp_subject_hash' => "OCSP Subject Hash",
    'ocsp_public_hash'  => "OCSP Public Hash",
    'subject_hash'  => "Subject Hash",
    'issuer_hash'   => "Issuer Hash",
    'fp_not_md5'    => "Fingerprint not MD5",
    'cert_type'     => "Certificate Type (bitmask)",
    'verify_hostname'   => "Hostname valid",
    'verify_altname'    => "AltNames valid",
    'fingerprint_hash'  => "Fingerprint Hash",
    'fingerprint_type'  => "Fingerprint Algorithm",
    'fingerprint_sha2'  => "Fingerprint SHA2",
    'fingerprint_sha1'  => "Fingerprint SHA1",
    'fingerprint_md5'   => "Fingerprint  MD5",
    'fingerprint'       => "Fingerprint:",
    'https_protocols'   => "HTTPS Alternate-Protocol",
    'https_body'    => "HTTPS Body",
    'https_svc'     => "HTTPS Alt-Svc header",
    'https_status'  => "HTTPS Status line",
    'https_server'  => "HTTPS Server banner",
    'https_location'=> "HTTPS Location header",
    'https_alerts'  => "HTTPS Error alerts",
    'https_refresh' => "HTTPS Refresh header",
    'https_pins'    => "HTTPS Public Key Pins",
    'https_sts'     => "HTTPS STS header",
    'hsts_maxage'   => "HTTPS STS MaxAge",
    'hsts_subdom'   => "HTTPS STS sub-domains",
    'hsts_preload'  => "HTTPS STS preload",
    'hsts_is301'    => "HTTP Status code is 301",
    'hsts_is30x'    => "HTTP Status code not 30x",
    'hsts_samehost' => "HTTP redirect to same host",
    'http_protocols'=> "HTTP Alternate-Protocol",
    'http_svc'      => "HTTP Alt-Svc header",
    'http_status'   => "HTTP Status line",
    'http_location' => "HTTP Location header",
    'http_refresh'  => "HTTP Refresh header",
    'http_sts'      => "HTTP STS header",
    'options'       => "<<internal>> SSL bitmask",
    #------------------+------------------------------------------------------
    # more texts dynamically, see "adding more shorttexts" below
); # %shorttexts
# add keys from %prot to %shorttext,
foreach my $ssl (keys %prot) {
    my $key = lc($ssl); # keys in data are all lowercase (see: convert all +CMD)
    $shorttexts{$key} = "Default $prot{$ssl}->{txt} cipher";
}

my %scores = (
    # keys starting with 'check_' are for total values
    # all other keys are for individual score values
    #------------------+-------------+----------------------------------------
    'check_conn'    => {'val' => 100, 'txt' => "SSL connection checks"},
    'check_ciph'    => {'val' => 100, 'txt' => "Ciphers checks"},
    'check_cert'    => {'val' => 100, 'txt' => "Certificate checks"},
    'check_dest'    => {'val' => 100, 'txt' => "Target checks"},
    'check_http'    => {'val' => 100, 'txt' => "HTTP(S) checks"},
    'check_size'    => {'val' => 100, 'txt' => "Certificate sizes checks"},
    'checks'        => {'val' => 100, 'txt' => "Total scoring"},
    #------------------+-------------+----------------------------------------
    # sorting according key name
); # %scores

my %score_ssllabs = (
    # SSL Server Rating Guide:
    #------------------+------------+---------------+-------------------------
    'check_prot'    => {'val' =>  0, 'score' => 0.3, 'txt' => "Protocol support"},        # 30%
    'check_keyx'    => {'val' =>  0, 'score' => 0.3, 'txt' => "Key exchange support"},    # 30%
    'check_ciph'    => {'val' =>  0, 'score' => 0.4, 'txt' => "Cipher strength support"}, # 40%
    # 'score' is a factor here; 'val' will be the score 0..100

    # Letter grade translation
    #                                           Grade  Numerical Score
    #------------------------------------------+------+---------------
    'A' => {'val' => 0, 'score' => 80, 'txt' => "A"}, # score >= 80
    'B' => {'val' => 0, 'score' => 65, 'txt' => "B"}, # score >= 65
    'C' => {'val' => 0, 'score' => 50, 'txt' => "C"}, # score >= 50
    'D' => {'val' => 0, 'score' => 35, 'txt' => "D"}, # score >= 35
    'E' => {'val' => 0, 'score' => 20, 'txt' => "E"}, # score >= 20
    'F' => {'val' => 0, 'score' => 20, 'txt' => "F"}, # score >= 20
     # 'val' is not used above!

    # Protocol support rating guide
    # Protocol                                  Score          Protocol
    #------------------------------------------+-----+------------------
    'SSLv2'         => {'val' =>  0, 'score' =>  20, 'txt' => "SSL 2.0"}, #  20%
    'SSLv3'         => {'val' =>  0, 'score' =>  80, 'txt' => "SSL 3.0"}, #  80%
    'TLSv1'         => {'val' =>  0, 'score' =>  90, 'txt' => "TLS 1.0"}, #  90%
    'TLSv11'        => {'val' =>  0, 'score' =>  95, 'txt' => "TLS 1.1"}, #  95%
    'TLSv12'        => {'val' =>  0, 'score' => 100, 'txt' => "TLS 1.2"}, # 100%
    'TLSv13'        => {'val' =>  0, 'score' => 100, 'txt' => "TLS 1.3"}, # 100%
    'DTLSv09'       => {'val' =>  0, 'score' =>  80, 'txt' => "DTLS 0.9"},#  80%
    'DTLSv1'        => {'val' =>  0, 'score' => 100, 'txt' => "DTLS 1.0"},# 100%
    'DTLSv11'       => {'val' =>  0, 'score' => 100, 'txt' => "DTLS 1.1"},# 100%
    'DTLSv12'       => {'val' =>  0, 'score' => 100, 'txt' => "DTLS 1.2"},# 100%
    'DTLSv13'       => {'val' =>  0, 'score' => 100, 'txt' => "DTLS 1.3"},# 100%
    # 'txt' is not used here!
    #
    #    ( best protocol + worst protocol ) / 2

    # Key exchange rating guide
    #                                           Score          Key exchange aspect                              # Score
    #------------------------------------------+-----+----------------------------------------------------------+------
    'key_debian'    => {'val' =>  0, 'score' =>   0, 'txt' => "Weak key (Debian OpenSSL flaw)"},                #   0%
    'key_anonx'     => {'val' =>  0, 'score' =>   0, 'txt' => "Anonymous key exchange (no authentication)"},    #   0%
    'key_512'       => {'val' =>  0, 'score' =>  20, 'txt' => "Key length < 512 bits"},                         #  20%
    'key_export'    => {'val' =>  0, 'score' =>  40, 'txt' => "Exportable key exchange (limited to 512 bits)"}, #  40%
    'key_1024'      => {'val' =>  0, 'score' =>  40, 'txt' => "Key length < 1024 bits (e.g., 512)"},            #  40%
    'key_2048'      => {'val' =>  0, 'score' =>  80, 'txt' => "Key length < 2048 bits (e.g., 1024)"},           #  80%
    'key_4096'      => {'val' =>  0, 'score' =>  90, 'txt' => "Key length < 4096 bits (e.g., 2048)"},           #  90%
    'key_good'      => {'val' =>  0, 'score' => 100, 'txt' => "Key length >= 4096 bits (e.g., 4096)"},          # 100%
    #
    #
    # Cipher strength rating guide
    #                                           Score          Cipher strength                # Score
    #------------------------------------------+-----+----------------------------------------+------
    'ciph_0'        => {'val' =>  0, 'score' =>   0, 'txt' => "0 bits (no encryption)"},      #   0%
    'ciph_128'      => {'val' =>  0, 'score' =>   0, 'txt' => "< 128 bits (e.g., 40, 56)"},   #  20%
    'ciph_256'      => {'val' =>  0, 'score' =>   0, 'txt' => "< 256 bits (e.g., 128, 168)"}, #  80%
    'ciph_512'      => {'val' =>  0, 'score' =>   0, 'txt' => ">= 256 bits (e.g., 256)"},     # 100%
    #
    #    ( strongest cipher + weakest cipher ) / 2
    #
); # %score_ssllabs

my %score_howsmyssl = (
    # https://www.howsmyssl.com/
    # https://www.howsmyssl.com/s/about.html
    'good'          => {'txt' => "Good"},
    'probably'      => {'txt' => "Probably Okay"},
    'improvable'    => {'txt' => "Improvable"},
        # if they do not support ephemeral key cipher suites,
        # do not support session tickets, or are using TLS 1.1.
    'bad'           => {'txt' => "Bad"},
        # uses TLS 1.0 (instead of 1.1 or 1.2), or worse: SSLv3 or earlier.
        # supports known insecure cipher suites
        # supports TLS compression (that is compression of the encryption
        #     information used to secure your connection) which exposes it
        #     to the CRIME attack.
        # is susceptible to the BEAST attack
); # %score_howsmyssl

my %info_gnutls = ( # NOT YET USED
   # extracted from http://www.gnutls.org/manual/gnutls.html
   #     security   parameter   ECC key
   #       bits       size       size    security    description
   #     ----------+-----------+--------+-----------+------------------
   'I' => "<72      <1008      <160      INSECURE    Considered to be insecure",
   'W' => "72        1008       160      WEAK        Short term protection against small organizations",
   'L' => "80        1248       160      LOW         Very short term protection against agencies",
   'l' => "96        1776       192      LEGACY      Legacy standard level",
   'M' => "112       2432       224      NORMAL      Medium-term protection",
   'H' => "128       3248       256      HIGH        Long term protection",
   'S' => "256       15424      512      ULTRA       Foreseeable future",
); # %info_gnutls

our %cmd = (
    'timeout'       => "timeout",   # to terminate shell processes (timeout 1)
    'openssl'       => "openssl",   # OpenSSL
    'libs'          => [],      # where to find libssl.so and libcrypto.so
    'path'          => [],      # where to find openssl executable
    'extopenssl'    => 1,       # 1: use external openssl; default yes, except on Win32
    'extsclient'    => 1,       # 1: use openssl s_client; default yes, except on Win32
    'extciphers'    => 0,       # 1: use openssl s_client -cipher for connection check
    'envlibvar'     => "LD_LIBRARY_PATH",       # name of environment variable
    'call'          => [],      # list of special (internal) function calls
                                # see --call=METHOD option in description below
);

#| construct list for special commands: 'cmd-*'
#| -------------------------------------
my $old   = "";
my $regex = join("|", @{$cfg{'versions'}}); # these are data only, not commands
foreach my $key (sort {uc($a) cmp uc($b)} keys %data, keys %checks, @{$cfg{'commands-INT'}}) {
    next if ($key eq $old); # unique
    $old  = $key;
    push(@{$cfg{'commands'}},  $key) if ($key !~ m/^(?:$regex)/);
    push(@{$cfg{'cmd-hsts'}},  $key) if ($key =~ m/$cfg{'regex'}->{'cmd-hsts'}/i);
    push(@{$cfg{'cmd-http'}},  $key) if ($key =~ m/$cfg{'regex'}->{'cmd-http'}/i);
    push(@{$cfg{'cmd-sizes'}}, $key) if ($key =~ m/$cfg{'regex'}->{'cmd-sizes'}/);
    push(@{$cfg{'need-checkhttp'}}, $key) if ($key =~ m/$cfg{'regex'}->{'cmd-hsts'}/);
    push(@{$cfg{'need-checkhttp'}}, $key) if ($key =~ m/$cfg{'regex'}->{'cmd-http'}/);
}

push(@{$cfg{'cmd-check'}}, $_) foreach (keys %checks);
push(@{$cfg{'cmd-info--v'}}, 'dump');       # more information
foreach my $key (keys %data) {
    push(@{$cfg{'cmd-info--v'}}, $key);
    next if (_is_intern($key) > 0);         # ignore aliases
    next if ($key =~ m/^(ciphers)/   and $verbose == 0); # Client ciphers are less important
    next if ($key =~ m/^modulus$/    and $verbose == 0); # same values as 'pubkey_value'
    push(@{$cfg{'cmd-info'}},    $key);
}
push(@{$cfg{'cmd-info--v'}}, 'info--v');

_yeast_TIME("cfg}");

# definitions here until moved to OSaft/Ciphers.pm
%ciphers = (
        #-----------------------------+------+-----+----+----+----+-----+--------+----+--------,
        #'head'                 => [qw(  sec  ssl   enc  bits mac  auth  keyx    score tags)],
        #-----------------------------+------+-----+----+----+----+-----+--------+----+--------,
        #'ADH-AES128-SHA'        => [qw(  HIGH SSLv3 AES   128 SHA1 None  DH         11 "")],
        #'ADH-AES256-SHA'        => [qw(  HIGH SSLv3 AES   256 SHA1 None  DH         11 "")],
        #'ADH-DES-CBC3-SHA'      => [qw(  HIGH SSLv3 3DES  168 SHA1 None  DH         11 "")],
        #'ADH-DES-CBC-SHA'       => [qw(   LOW SSLv3 DES    56 SHA1 None  DH         11 "")],
        #'ADH-RC4-MD5'           => [qw(MEDIUM SSLv3 RC4   128 MD5  None  DH         11 "")],
        #'ADH-SEED-SHA'          => [qw(MEDIUM SSLv3 SEED  128 SHA1 None  DH         11 "")],
        #   above use anonymous DH and hence are vulnerable to MiTM attacks
        #   see openssl's `man ciphers' for details (eNULL and aNULL)
        #   so they are qualified   weak  here instead of the definition
        #   in  `openssl ciphers -v HIGH'
        #--------
        # values  -?-  are unknown yet
        #!#---------------------------+------+-----+----+----+----+-----+--------+----+--------,
        #!# 'head'              => [qw(  sec  ssl   enc  bits mac  auth  keyx    score tags)],
        #!#---------------------------+------+-----+----+----+----+-----+--------+----+--------,
 # FIXME: Perl hashes may not have multiple keys (have them for SSLv2 and SSLv3)
        'ADH-AES128-SHA'        => [qw(  weak SSLv3 AES   128 SHA1 None  DH          0 :)],
        'ADH-AES256-SHA'        => [qw(  weak SSLv3 AES   256 SHA1 None  DH          0 :)],
        'ADH-DES-CBC3-SHA'      => [qw(  weak SSLv3 3DES  168 SHA1 None  DH          0 :)],
        'ADH-DES-CBC-SHA'       => [qw(  weak SSLv3 DES    56 SHA1 None  DH          0 :)],
        'ADH-RC4-MD5'           => [qw(  weak SSLv3 RC4   128 MD5  None  DH          0 :)], # openssl: MEDIUM
        'ADH-SEED-SHA'          => [qw(  weak SSLv3 SEED  128 SHA1 None  DH          0 OSX)], # openssl: MEDIUM
        #
        'AECDH-AES128-SHA'      => [qw(  weak SSLv3 AES   128 SHA1 None  ECDH       11 :)],
        'AECDH-AES256-SHA'      => [qw(  weak SSLv3 AES   256 SHA1 None  ECDH       11 :)],
        'AECDH-DES-CBC3-SHA'    => [qw(  weak SSLv3 3DES  168 SHA1 None  ECDH        0 :)],
        'AECDH-NULL-SHA'        => [qw(  weak SSLv3 None    0 SHA1 None  ECDH        0 :)],
        'AECDH-RC4-SHA'         => [qw(  weak SSLv3 RC4   128 SHA1 None  ECDH       11 :)], # openssl: MEDIUM
        'AES128-SHA'            => [qw(  HIGH SSLv3 AES   128 SHA1 RSA   RSA        80 :)],
        'AES256-SHA'            => [qw(  HIGH SSLv3 AES   256 SHA1 RSA   RSA       100 :)],
        'DES-CBC3-MD5'          => [qw(  weak SSLv2 3DES  168 MD5  RSA   RSA         0 :)],
        'DES-CBC3-SHA'          => [qw(  weak SSLv3 3DES  168 SHA1 RSA   RSA         0 :)],
        'DES-CBC3-SHA'          => [qw(  weak SSLv2 3DES  168 SHA1 RSA   RSA         0 :)],
        'DES-CBC-MD5'           => [qw(  weak SSLv2 DES    56 MD5  RSA   RSA         0 :)],
        'DES-CBC-SHA'           => [qw(  weak SSLv3 DES    56 SHA1 RSA   RSA         0 :)],
        'DES-CBC-SHA'           => [qw(  weak SSLv2 DES    56 SHA1 RSA   RSA         0 :)],
        'DES-CFB-M1'            => [qw(  weak SSLv2 DES    64 MD5  RSA   RSA        20 :)],
        'DH-DSS-AES128-SHA'     => [qw(medium -?-   AES   128 SHA1 DSS   DH         81 :)],
        'DH-DSS-AES256-SHA'     => [qw(medium -?-   AES   256 SHA1 DSS   DH         81 :)],
        'DH-RSA-AES128-SHA'     => [qw(medium -?-   AES   128 SHA1 RSA   DH         81 :)],
        'DH-RSA-AES256-SHA'     => [qw(medium -?-   AES   256 SHA1 RSA   DH         81 :)],
        'DHE-DSS-AES128-SHA'    => [qw(  HIGH SSLv3 AES   128 SHA1 DSS   DH         80 :)],
        'DHE-DSS-AES256-SHA'    => [qw(  HIGH SSLv3 AES   256 SHA1 DSS   DH        100 :)],
        'DHE-DSS-RC4-SHA'       => [qw(  weak SSLv3 RC4   128 SHA1 DSS   DH         20 :)],
            # see SSLlabs.com:
            # https://www.ssllabs.com/ssltest/viewClient.html?name=IE&version=11&platform=Win%208.1
            # ...  Cannot be used for Forward Secrecy because they require DSA
            #      keys, which are effectively limited to 1024 bits.
        'DHE-DSS-SEED-SHA'      => [qw(MEDIUM SSLv3 SEED  128 SHA1 DSS   DH         81 OSX)],
        'DHE-RSA-AES128-SHA'    => [qw(  HIGH SSLv3 AES   128 SHA1 RSA   DH         80 :)],
        'DHE-RSA-AES256-SHA'    => [qw(  HIGH SSLv3 AES   256 SHA1 RSA   DH        100 :)],
        'DHE-RSA-SEED-SHA'      => [qw(MEDIUM SSLv3 SEED  128 SHA1 RSA   DH         81 OSX)],
        'ECDH-ECDSA-AES128-SHA' => [qw(  HIGH SSLv3 AES   128 SHA1 ECDH  ECDH/ECDSA 91 :)],
        'ECDH-ECDSA-AES256-SHA' => [qw(  HIGH SSLv3 AES   256 SHA1 ECDH  ECDH/ECDSA 91 :)],
        'ECDH-ECDSA-DES-CBC3-SHA'=>[qw(  weak SSLv3 3DES  168 SHA1 ECDH  ECDH/ECDSA  0 :)],
        'ECDH-ECDSA-RC4-SHA'    => [qw(  weak SSLv3 RC4   128 SHA1 ECDH  ECDH/ECDSA 81 :)], #openssl: MEDIUM
        'ECDH-ECDSA-NULL-SHA'   => [qw(  weak SSLv3 None    0 SHA1 ECDH  ECDH/ECDSA  0 :)],
        'ECDH-RSA-AES128-SHA'   => [qw(  HIGH SSLv3 AES   128 SHA1 ECDH  ECDH/RSA   11 :)],
        'ECDH-RSA-AES256-SHA'   => [qw(  HIGH SSLv3 AES   256 SHA1 ECDH  ECDH/RSA   11 :)],
        'ECDH-RSA-DES-CBC3-SHA' => [qw(  weak SSLv3 3DES  168 SHA1 ECDH  ECDH/RSA    0 :)],
        'ECDH-RSA-RC4-SHA'      => [qw(  weak SSLv3 RC4   128 SHA1 ECDH  ECDH/RSA   81 :)], #openssl: MEDIUM
        'ECDH-RSA-NULL-SHA'     => [qw(  weak SSLv3 None    0 SHA1 ECDH  ECDH/RSA    0 :)],
        'ECDHE-ECDSA-AES128-SHA'=> [qw(  HIGH SSLv3 AES   128 SHA1 ECDSA ECDH       11 :)],
        'ECDHE-ECDSA-AES256-SHA'=> [qw(  HIGH SSLv3 AES   256 SHA1 ECDSA ECDH       11 :)],
        'ECDHE-ECDSA-DES-CBC3-SHA'=> [qw(weak SSLv3 3DES  168 SHA1 ECDSA ECDH        0 :)],
        'ECDHE-ECDSA-NULL-SHA'  => [qw(  weak SSLv3 None    0 SHA1 ECDSA ECDH        0 :)],
        'ECDHE-ECDSA-RC4-SHA'   => [qw(  weak SSLv3 RC4   128 SHA1 ECDSA ECDH       81 :)], #openssl: MEDIUM
        'ECDHE-RSA-AES128-SHA'  => [qw(  HIGH SSLv3 AES   128 SHA1 RSA   ECDH       11 :)],
        'ECDHE-RSA-AES256-SHA'  => [qw(  HIGH SSLv3 AES   256 SHA1 RSA   ECDH       11 :)],
        'ECDHE-RSA-DES-CBC3-SHA'=> [qw(  weak SSLv3 3DES  168 SHA1 RSA   ECDH        0 :)],
        'ECDHE-RSA-RC4-SHA'     => [qw(  weak SSLv3 RC4   128 SHA1 RSA   ECDH       81 :)], #openssl: MEDIUM
        'ECDHE-RSA-NULL-SHA'    => [qw(  weak SSLv3 None    0 SHA1 RSA   ECDH        0 :)],
        'EDH-DSS-DES-CBC3-SHA'  => [qw(  weak SSLv3 3DES  168 SHA1 DSS   DH          0 :)],
        'EDH-DSS-DES-CBC-SHA'   => [qw(  weak SSLv3 DES    56 SHA1 DSS   DH          0 :)],
        'EDH-RSA-DES-CBC3-SHA'  => [qw(  weak SSLv3 3DES  168 SHA1 RSA   DH          0 :)],
        'EDH-RSA-DES-CBC-SHA'   => [qw(  weak SSLv3 DES    56 SHA1 RSA   DH          0 :)],
        'EXP-ADH-DES-CBC-SHA'   => [qw(  weak SSLv3 DES    40 SHA1 None  DH(512)     0 export)],
        'EXP-ADH-RC4-MD5'       => [qw(  weak SSLv3 RC4    40 MD5  None  DH(512)     0 export)],
        'EXP-DES-CBC-SHA'       => [qw(  weak SSLv3 DES    40 SHA1 RSA   RSA(512)    0 export)],
        'EXP-EDH-DSS-DES-CBC-SHA'=>[qw(  weak SSLv3 DES    40 SHA1 DSS   DH(512)     0 export)],
        'EXP-EDH-RSA-DES-CBC-SHA'=>[qw(  weak SSLv3 DES    40 SHA1 RSA   DH(512)     0 export)],
        'EXP-RC2-CBC-MD5'       => [qw(  weak SSLv2 RC2    40 MD5  RSA   RSA(512)    0 export)],
        'EXP-RC2-CBC-MD5'       => [qw(  weak SSLv3 RC2    40 MD5  RSA   RSA(512)    0 export)],
        'EXP-RC4-MD5'           => [qw(  WEAK SSLv2 RC4    40 MD5  RSA   RSA(512)    2 export)],
        'EXP-RC4-MD5'           => [qw(  WEAK SSLv3 RC4    40 MD5  RSA   RSA(512)    2 export)],
        'EXP-RC4-64-MD5'        => [qw(  weak SSLv3 RC4    64 MD5  DSS   RSA         2 :)], # (from RSA BSAFE SSL-C)
        'EXP-EDH-DSS-RC4-56-SHA'=> [qw(  WEAK SSLv3 RC4    56 SHA  DSS   DHE         2 :)], # (from RSA BSAFE SSL-C)
        'EXP1024-DES-CBC-SHA'   => [qw(  weak SSLv3 DES    56 SHA1 RSA   RSA(1024)   0 export)],
        'EXP1024-DHE-DSS-RC4-SHA'=>[qw(  WEAK SSLv3 RC4    56 SHA1 DSS   DH(1024)    2 export)],
        'EXP1024-DHE-DSS-DES-CBC-SHA' => [qw(weak SSLv3 DES 56 SHA1 DSS  DH(1024)    0 export)],
        'EXP1024-RC2-CBC-MD5'   => [qw(  weak SSLv3 RC2    56 MD5  RSA   RSA(1024)   0 export)],
        'EXP1024-RC4-MD5'       => [qw(  WEAK SSLv3 RC4    56 MD5  RSA   RSA(1024)   1 export)],
        'EXP1024-RC4-SHA'       => [qw(  WEAK SSLv3 RC4    56 SHA1 RSA   RSA(1024)   2 export)],
        'IDEA-CBC-MD5'          => [qw(  weak SSLv2 IDEA  128 MD5  RSA   RSA         0 :)],
        'IDEA-CBC-SHA'          => [qw(  weak SSLv2 IDEA  128 SHA1 RSA   RSA         0 :)],
        'NULL'                  => [qw(  weak SSLv2 None    0 -?-  None  -?-         0 :)], # openssl SSLeay testing
        'NULL-MD5'              => [qw(  weak SSLv2 None    0 MD5  RSA   RSA(512)    0 :)],
        'NULL-MD5'              => [qw(  weak SSLv3 None    0 MD5  RSA   RSA(512)    0 export)], # FIXME: same hash key as before
        'NULL-SHA'              => [qw(  weak SSLv3 None    0 SHA1 RSA   RSA         0 :)],
        'RSA-PSK-AES128-CBC-SHA'=> [qw(  HIGH SSLv3 AES   128 SHA1 AES   RSAPSK      0 :)],
#       'RSA-PSK-AES128-SHA'    => [qw(  HIGH SSLv3 AES   128 SHA1 AES   RSAPSK      0 :)], # same as RSA-PSK-AES128-CBC-SHA
        'RSA-PSK-AES256-CBC-SHA'=> [qw(  HIGH SSLv3 RSA   256 SHA1 AES   RSAPSK      0 :)],
#       'RSA-PSK-AES256-SHA    '=> [qw(  HIGH SSLv3 RSA   256 SHA1 AES   RSAPSK      0 :)], # same as RSA-PSK-AES128-CBC-SHA
        'RSA-PSK-3DES-EDE-CBC-SHA'=>[qw( weak SSLv3 3DES  168 SHA1 RSA   RSAPSK      0 :)],
#       'RSA-PSK-3DES-SHA'      => [qw(  weak SSLv3 3DES  168 SHA1 RSA   RSAPSK      0 :)], # same as RSA-PSK-3DES-EDE-CBC-SHA
        'PSK-3DES-EDE-CBC-SHA'  => [qw(  weak SSLv3 3DES  168 SHA1 PSK   PSK         0 :)],
        'PSK-AES128-CBC-SHA'    => [qw(  HIGH SSLv3 AES   128 SHA1 PSK   PSK         0 :)],
        'PSK-AES256-CBC-SHA'    => [qw(  HIGH SSLv3 AES   256 SHA1 PSK   PSK         0 :)],
        'RSA-PSK-RC4-SHA'       => [qw(MEDIUM SSLv3 RC4   128 SHA1 RSA   RSAPSK     80 :)],
        'PSK-RC4-SHA'           => [qw(MEDIUM SSLv3 RC4   128 SHA1 PSK   PSK        80 :)],
        'RC2-CBC-MD5'           => [qw(  weak SSLv2 RC2   128 MD5  RSA   RSA         0 :)],
        'RC2-MD5'               => [qw(MEDIUM SSLv2 RC2   128 MD5  RSA   RSA        80 :)],
        'RC4-64-MD5'            => [qw(  weak SSLv2 RC4    64 MD5  RSA   RSA         3 :)],
        'RC4-MD5'               => [qw(  weak SSLv2 RC4   128 MD5  RSA   RSA         8 :)], #openssl: MEDIUM
        'RC4-MD5'               => [qw(  weak SSLv3 RC4   128 MD5  RSA   RSA         8 :)], #openssl: MEDIUM
        'RC4-SHA'               => [qw(  weak SSLv3 RC4   128 SHA1 RSA   RSA         8 :)], #openssl: MEDIUM
        'SEED-SHA'              => [qw(MEDIUM SSLv3 SEED  128 SHA1 RSA   RSA        11 OSX)],
        #-----------------------------+------+-----+----+----+----+-----+--------+----+--------,
        'ADH-CAMELLIA128-SHA'   => [qw(  weak SSLv3 CAMELLIA  128 SHA1 None  DH      0 :)], #openssl: HIGH
        'ADH-CAMELLIA256-SHA'   => [qw(  weak SSLv3 CAMELLIA  256 SHA1 None  DH      0 :)], #openssl: HIGH
        'CAMELLIA128-SHA'       => [qw(  HIGH SSLv3 CAMELLIA  128 SHA1 RSA   RSA    80 :)],
        'CAMELLIA256-SHA'       => [qw(  HIGH SSLv3 CAMELLIA  256 SHA1 RSA   RSA   100 :)],
        'DHE-DSS-CAMELLIA128-SHA'=>[qw(  HIGH SSLv3 CAMELLIA  128 SHA1 DSS   DH     80 :)],
        'DHE-DSS-CAMELLIA256-SHA'=>[qw(  HIGH SSLv3 CAMELLIA  256 SHA1 DSS   DH    100 :)],
        'DHE-RSA-CAMELLIA128-SHA'=>[qw(  HIGH SSLv3 CAMELLIA  128 SHA1 RSA   DH     80 :)],
        'DHE-RSA-CAMELLIA256-SHA'=>[qw(  HIGH SSLv3 CAMELLIA  256 SHA1 RSA   DH    100 :)],
        'GOST2001-GOST89-GOST89'=> [qw(  HIGH SSLv3 GOST89 256 GOST89  GOST01 GOST 100 :)],
        'GOST94-GOST89-GOST89'  => [qw(  HIGH SSLv3 GOST89 256 GOST89  GOST94 GOST 100 :)],
        'GOST-GOST89STREAM'     => [qw(  HIGH SSLv3 GOST89 256 GOST89  RSA    RSA  100 :)],
        'GOST-GOST89MAC'        => [qw(  HIGH SSLv3 GOST89 256 GOST89  RSA    RSA  100 :)],
        'GOST-GOST94'           => [qw(  HIGH SSLv3 GOST89 256 GOST94  RSA    RSA  100 :)],
        'GOST-MD5'              => [qw(  weak SSLv3 GOST89 256 MD5     RSA    RSA    0 :)], #openssl: HIGH
        'GOST2001-NULL-GOST94'  => [qw(  HIGH SSLv3 None     0 GOST94  GOST01 GOST 100 :)],
        'GOST94-NULL-GOST94'    => [qw(  HIGH SSLv3 None     0 GOST94  GOST94 GOST 100 :)],
        #-----------------------------+------+-----+----+----+----+-----+--------+----+--------,

        # from openssl-1.0.1c
        #!#-----------------------------------+------+-----+------+---+------+-----+--------+----+--------,
        #!# 'head'                      => [qw(  sec  ssl   enc   bits mac    auth  keyx    score tags)],
        #!#-----------------------------------+------+-----+------+---+------+-----+--------+----+--------,
        'SRP-AES-128-CBC-SHA'           => [qw(  HIGH SSLv3 AES    128 SHA1   None  SRP         0 :)], # openssl: HIGH
        'SRP-AES-256-CBC-SHA'           => [qw(  HIGH SSLv3 AES    256 SHA1   None  SRP         0 :)], # openssl: HIGH
        'SRP-DSS-3DES-EDE-CBC-SHA'      => [qw(  weak SSLv3 3DES   168 SHA1   DSS   SRP         0 :)],
        'SRP-DSS-AES-128-CBC-SHA'       => [qw(  HIGH SSLv3 AES    128 SHA1   DSS   SRP         0 :)],
        'SRP-DSS-AES-256-CBC-SHA'       => [qw(  HIGH SSLv3 AES    256 SHA1   DSS   SRP         0 :)],
        'SRP-RSA-3DES-EDE-CBC-SHA'      => [qw(  weak SSLv3 3DES   168 SHA1   RSA   SRP         0 :)],
        'SRP-RSA-AES-128-CBC-SHA'       => [qw(  HIGH SSLv3 AES    128 SHA1   RSA   SRP         0 :)],
        'SRP-RSA-AES-256-CBC-SHA'       => [qw(  HIGH SSLv3 AES    256 SHA1   RSA   SRP         0 :)],
        'SRP-3DES-EDE-CBC-SHA'          => [qw(  weak SSLv3 3DES   168 SHA1   None  SRP         0 :)], # openssl: HIGH
        'ADH-AES128-SHA256'             => [qw( weak TLSv12 AES    128 SHA256 None  DH         10 :)], # openssl: HIGH
        'ADH-AES128-GCM-SHA256'         => [qw( weak TLSv12 AESGCM 128 AEAD   None  DH         10 :)], # openssl: HIGH
        'ADH-AES256-GCM-SHA384'         => [qw( weak TLSv12 AESGCM 256 AEAD   None  DH         10 :)], # openssl: HIGH
        'ADH-AES256-SHA256'             => [qw( weak TLSv12 AES    256 SHA256 None  DH         10 :)], # openssl: HIGH
        'AES128-GCM-SHA256'             => [qw( HIGH TLSv12 AESGCM 128 AEAD   RSA   RSA        91 :)],
        'AES128-SHA256'                 => [qw( HIGH TLSv12 AES    128 SHA256 RSA   RSA        91 :)],
        'AES256-GCM-SHA384'             => [qw( HIGH TLSv12 AESGCM 256 AEAD   RSA   RSA        91 :)],
        'AES256-SHA256'                 => [qw( HIGH TLSv12 AES    256 SHA256 RSA   RSA        91 :)],
        'DHE-DSS-AES128-GCM-SHA256'     => [qw( HIGH TLSv12 AESGCM 128 AEAD   DSS   DH         91 :)],
        'DHE-DSS-AES128-SHA256'         => [qw( HIGH TLSv12 AES    128 SHA256 DSS   DH         91 :)],
        'DHE-DSS-AES256-GCM-SHA384'     => [qw( HIGH TLSv12 AESGCM 256 AEAD   DSS   DH         91 :)],
        'DHE-DSS-AES256-SHA256'         => [qw( HIGH TLSv12 AES    256 SHA256 DSS   DH         91 :)],
        'DHE-RSA-AES128-GCM-SHA256'     => [qw( HIGH TLSv12 AESGCM 128 AEAD   RSA   DH         91 :)],
        'DHE-RSA-AES128-SHA256'         => [qw( HIGH TLSv12 AES    128 SHA256 RSA   DH         91 :)],
        'DHE-RSA-AES256-GCM-SHA384'     => [qw( HIGH TLSv12 AESGCM 256 AEAD   RSA   DH         91 :)],
        'DHE-RSA-AES256-SHA256'         => [qw( HIGH TLSv12 AES    256 SHA256 RSA   DH         91 :)],
        'ECDH-ECDSA-AES128-GCM-SHA256'  => [qw( HIGH TLSv12 AESGCM 128 AEAD   ECDH  ECDH/ECDSA 91 :)],
        'ECDH-ECDSA-AES128-SHA256'      => [qw( HIGH TLSv12 AES    128 SHA256 ECDH  ECDH/ECDSA 91 :)],
        'ECDH-ECDSA-AES256-GCM-SHA384'  => [qw( HIGH TLSv12 AESGCM 256 AEAD   ECDH  ECDH/ECDSA 91 :)],
        'ECDH-ECDSA-AES256-SHA384'      => [qw( HIGH TLSv12 AES    256 SHA384 ECDH  ECDH/ECDSA 91 :)],
        'ECDHE-ECDSA-AES128-GCM-SHA256' => [qw( HIGH TLSv12 AESGCM 128 AEAD   ECDSA ECDH       91 :)],
        'ECDHE-ECDSA-AES128-SHA256'     => [qw( HIGH TLSv12 AES    128 SHA256 ECDSA ECDH       91 :)],
        'ECDHE-ECDSA-AES256-GCM-SHA384' => [qw( HIGH TLSv12 AESGCM 256 AEAD   ECDSA ECDH       91 :)],
        'ECDHE-ECDSA-AES256-SHA384'     => [qw( HIGH TLSv12 AES    256 SHA384 ECDSA ECDH       91 :)],
        'ECDHE-RSA-AES128-GCM-SHA256'   => [qw( HIGH TLSv12 AESGCM 128 AEAD   RSA   ECDH       91 :)],
        'ECDHE-RSA-AES128-SHA256'       => [qw( HIGH TLSv12 AES    128 SHA256 RSA   ECDH       91 :)],
        'ECDHE-RSA-AES256-GCM-SHA384'   => [qw( HIGH TLSv12 AESGCM 256 AEAD   RSA   ECDH       91 :)],
        'ECDHE-RSA-AES256-SHA384'       => [qw( HIGH TLSv12 AES    256 SHA384 RSA   ECDH       91 :)],
        'ECDH-RSA-AES128-GCM-SHA256'    => [qw( HIGH TLSv12 AESGCM 128 AEAD   ECDH  ECDH/RSA   91 :)],
        'ECDH-RSA-AES128-SHA256'        => [qw( HIGH TLSv12 AES    128 SHA256 ECDH  ECDH/RSA   91 :)],
        'ECDH-RSA-AES256-GCM-SHA384'    => [qw( HIGH TLSv12 AESGCM 256 AEAD   ECDH  ECDH/RSA   91 :)],
        'ECDH-RSA-AES256-SHA384'        => [qw( HIGH TLSv12 AES    256 SHA384 ECDH  ECDH/RSA   91 :)],
        'NULL-SHA256'                   => [qw( weak TLSv12 None     0 SHA256 RSA   RSA         0 :)],
        #-------------------------------------+------+-----+------+---+------+-----+--------+----+--------,

        # from openssl-1.0.2d
        #!#-----------------------------------+------+-----+------+---+------+-----+--------+----+--------,
        #!# 'head'                      => [qw(  sec  ssl   enc   bits mac    auth  keyx    score tags)],
        #!#-----------------------------------+------+-----+------+---+------+-----+--------+----+--------,
        'ADH-CAMELLIA128-SHA256'        => [qw( weak TLSv12 CAMELLIA 128 SHA256 None  DH        0 :)], #openssl: HIGH
        'ADH-CAMELLIA256-SHA256'        => [qw( weak TLSv12 CAMELLIA 256 SHA256 None  DH        0 :)], #openssl: HIGH
        'CAMELLIA128-SHA256'            => [qw( HIGH TLSv12 CAMELLIA 128 SHA256 RSA   RSA      80 :)],
        'CAMELLIA256-SHA256'            => [qw( HIGH TLSv12 CAMELLIA 256 SHA256 RSA   RSA     100 :)],
        'DHE-DSS-CAMELLIA128-SHA256'    => [qw( HIGH TLSv12 CAMELLIA 128 SHA256 DSS   DH       80 :)],
        'DHE-DSS-CAMELLIA256-SHA256'    => [qw( HIGH TLSv12 CAMELLIA 256 SHA256 DSS   DH      100 :)],
        'DHE-RSA-CAMELLIA128-SHA256'    => [qw( HIGH TLSv12 CAMELLIA 128 SHA256 RSA   DH       80 :)],
        'DHE-RSA-CAMELLIA256-SHA256'    => [qw( HIGH TLSv12 CAMELLIA 256 SHA256 RSA   DH      100 :)],
        'DH-DSS-CAMELLIA128-SHA'        => [qw( HIGH  SSLv3 CAMELLIA 128 SHA1   DSS   DH       90 :)],
        'DH-RSA-CAMELLIA128-SHA'        => [qw( HIGH  SSLv3 CAMELLIA 128 SHA1   RSA   DH       90 :)],
        'DH-DSS-CAMELLIA128-SHA256'     => [qw( HIGH TLSv12 CAMELLIA 128 SHA256 DSS   DH       90 :)],
        'DH-RSA-CAMELLIA128-SHA256'     => [qw( HIGH TLSv12 CAMELLIA 128 SHA256 RSA   DH       90 :)],
        'DH-DSS-CAMELLIA256-SHA'        => [qw( HIGH  SSLv3 CAMELLIA 256 SHA1   DH    DSS     100 :)], # openssl 1.0.2-chacha; auth=DH ??
        'DH-RSA-CAMELLIA256-SHA'        => [qw( HIGH  SSLv3 CAMELLIA 256 SHA1   DH    RSA     100 :)], # openssl 1.0.2-chacha; auth=DH ??
        'DH-DSS-CAMELLIA256-SHA256'     => [qw( HIGH TLSv12 CAMELLIA 256 SHA256 DH    DSS     100 :)], # openssl 1.0.2-chacha; auth=DH ??
        'DH-RSA-CAMELLIA256-SHA256'     => [qw( HIGH TLSv12 CAMELLIA 256 SHA256 DH    RSA     100 :)], # openssl 1.0.2-chacha; auth=DH ??
        'ECDHE-RSA-CAMELLIA128-SHA256'  => [qw( HIGH TLSv12 CAMELLIA 128 SHA256 RSA   ECDH    100 :)],
        'ECDHE-RSA-CAMELLIA256-SHA384'  => [qw( HIGH TLSv12 CAMELLIA 256 SHA384 RSA   ECDH    100 :)],
        'ECDHE-ECDSA-CAMELLIA128-SHA256'=> [qw( HIGH TLSv12 CAMELLIA 128 SHA256 ECDSA ECDH    100 :)],
        'ECDHE-ECDSA-CAMELLIA256-SHA384'=> [qw( HIGH TLSv12 CAMELLIA 256 SHA384 ECDSA ECDH    100 :)],
        'ECDH-RSA-CAMELLIA128-SHA256'   => [qw( HIGH TLSv12 CAMELLIA 128 SHA256 ECDH  ECDH/RSA   100 :)],
        'ECDH-RSA-CAMELLIA256-SHA384'   => [qw( HIGH TLSv12 CAMELLIA 256 SHA384 ECDH  ECDH/RSA   100 :)],
        'ECDH-ECDSA-CAMELLIA128-SHA256' => [qw( HIGH TLSv12 CAMELLIA 128 SHA256 ECDH  ECDH/ECDSA 100 :)],
        'ECDH-ECDSA-CAMELLIA256-SHA384' => [qw( HIGH TLSv12 CAMELLIA 256 SHA384 ECDH  ECDH/ECDSA 100 :)],
        'DHE-RSA-CHACHA20-POLY1305-SHA256'     => [qw( HIGH TLSv12 ChaCha20-Poly1305 256 AEAD RSA   DH    1 :)], # openssl 1.0.2 DHE-RSA-CHACHA20-POLY1305
        'ECDHE-RSA-CHACHA20-POLY1305-SHA256'   => [qw( HIGH TLSv12 ChaCha20-Poly1305 256 AEAD RSA   ECDH  1 :)], # openssl 1.0.2 ECDHE-RSA-CHACHA20-POLY1305
        'ECDHE-ECDSA-CHACHA20-POLY1305-SHA256' => [qw( HIGH TLSv12 ChaCha20-Poly1305 256 AEAD ECDSA ECDH  1 :)], # openssl 1.0.2 ECDHE-ECDSA-CHACHA20-POLY1305
        'DHE-RSA-CHACHA20-POLY1305'     => [qw( HIGH TLSv12 ChaCha20-Poly1305 256 AEAD RSA   DH    1 :)], # bugfix for openssl 1.0.2
        'ECDHE-RSA-CHACHA20-POLY1305'   => [qw( HIGH TLSv12 ChaCha20-Poly1305 256 AEAD RSA   ECDH  1 :)], # bugfix for openssl 1.0.2
        'ECDHE-ECDSA-CHACHA20-POLY1305' => [qw( HIGH TLSv12 ChaCha20-Poly1305 256 AEAD ECDSA ECDH  1 :)], # bugfix for openssl 1.0.2
        'DHE-RSA-CHACHA20-POLY1305-OLD'       => [qw( HIGH TLSv12 ChaCha20-Poly1305 256 AEAD RSA   DH    1 :)], # openssl 1.0.2k-dev (patched version)
        'ECDHE-RSA-CHACHA20-POLY1305-OLD'     => [qw( HIGH TLSv12 ChaCha20-Poly1305 256 AEAD RSA   ECDH  1 :)], # openssl 1.0.2k-dev (patched version)
        'ECDHE-ECDSA-CHACHA20-POLY1305-OLD'   => [qw( HIGH TLSv12 ChaCha20-Poly1305 256 AEAD ECDSA ECDH  1 :)], # openssl 1.0.2k-dev (patched version)
        #!#-----------------------------------+------+-----+------+---+------+-----+--------+----+--------,

        # from http://tools.ietf.org/html/draft-mavrogiannopoulos-chacha-tls-01
        'RSA-CHACHA20-SHA'              => [qw( HIGH TLSv12 ChaCha20 256 SHA1 RSA   RSA         1 :)],
        'ECDHE-RSA-CHACHA20-SHA'        => [qw( HIGH TLSv12 ChaCha20 256 SHA1 RSA   ECDH        1 :)],
        'ECDHE-ECDSA-CHACHA20-SHA'      => [qw( HIGH TLSv12 ChaCha20 256 SHA1 RSA   ECDH        1 :)],
        'DHE-RSA-CHACHA20-SHA'          => [qw( HIGH TLSv12 ChaCha20 256 SHA1 RSA   DH          1 :)],
        'DHE-PSK-CHACHA20-SHA'          => [qw( HIGH TLSv12 ChaCha20 256 SHA1 PSK   DH          1 :)],
        'PSK-CHACHA20-SHA'              => [qw( HIGH TLSv12 ChaCha20 256 SHA1 PSK   PSK         1 :)],
        'ECDHE-PSK-CHACHA20-SHA'        => [qw( HIGH TLSv12 ChaCha20 256 SHA1 RSA   ECDH        1 :)],
        'RSA-PSK-CHACHA20-SHA'          => [qw( HIGH TLSv12 ChaCha20 256 SHA1 RSA   RSAPSK      1 :)],


        # from https://tools.ietf.org/html/draft-ietf-tls-chacha20-poly1305-04 (16. Dec 2015)
        'PSK-CHACHA20-POLY1305-SHA256'  => [qw( HIGH TLSv12 ChaCha20-Poly1305 256 AEAD PSK   PSK   1 :)],
        'ECDHE-PSK-CHACHA20-POLY1305-SHA256'=> [qw( HIGH TLSv12 ChaCha20-Poly1305 256 AEAD ECDHE ECDHEPSK 1 :)],
        'DHE-PSK-CHACHA20-POLY1305-SHA256'  => [qw( HIGH TLSv12 ChaCha20-Poly1305 256 AEAD DHE   DHEPSK 1 :)],
        'RSA-PSK-CHACHA20-POLY1305-SHA256'  => [qw( HIGH TLSv12 ChaCha20-Poly1305 256 AEAD RSA   RSAPSK 1 :)],

        # from http://tools.ietf.org/html/rfc6655
        'RSA-AES128-CCM'                => [qw( high TLSv12 AESCCM 128 AEAD   RSA   RSA        91 :)],
        'RSA-AES256-CCM'                => [qw( high TLSv12 AESCCM 256 AEAD   RSA   RSA        91 :)],
        'DHE-RSA-AES128-CCM'            => [qw( high TLSv12 AESCCM 128 AEAD   RSA   DH         91 :)],
        'DHE-RSA-AES256-CCM'            => [qw( high TLSv12 AESCCM 256 AEAD   RSA   DH         91 :)],
        'PSK-RSA-AES128-CCM'            => [qw( high TLSv12 AESCCM 128 AEAD   PSK   PSK        91 :)],
        'PSK-RSA-AES256-CCM'            => [qw( high TLSv12 AESCCM 256 AEAD   PSK   PSK        91 :)],
        'ECDHE-RSA-AES128-CCM'          => [qw( high TLSv12 AESCCM 128 AEAD   ECDSA ECDH       91 :)],
        'ECDHE-RSA-AES256-CCM'          => [qw( high TLSv12 AESCCM 256 AEAD   ECDSA ECDH       91 :)],
        'RSA-AES128-CCM-8'              => [qw( high TLSv12 AESCCM 128 AEAD   RSA   RSA        91 :)],
        'RSA-AES256-CCM-8'              => [qw( high TLSv12 AESCCM 256 AEAD   RSA   RSA        91 :)],
        'DHE-RSA-AES128-CCM-8'          => [qw( high TLSv12 AESCCM 128 AEAD   RSA   DH         91 :)],
        'DHE-RSA-AES256-CCM-8'          => [qw( high TLSv12 AESCCM 256 AEAD   RSA   DH         91 :)],
        'PSK-RSA-AES128-CCM-8'          => [qw( high TLSv12 AESCCM 128 AEAD   PSK   PSK        91 :)],
        'PSK-RSA-AES256-CCM-8'          => [qw( high TLSv12 AESCCM 256 AEAD   PSK   PSK        91 :)],
        'ECDHE-RSA-AES128-CCM-8'        => [qw( high TLSv12 AESCCM 128 AEAD   ECDSA ECDH       91 :)],
        'ECDHE-RSA-AES256-CCM-8'        => [qw( high TLSv12 AESCCM 256 AEAD   ECDSA ECDH       91 :)],
        # from: http://botan.randombit.net/doxygen/tls__suite__info_8cpp_source.html
        #/ RSA_WITH_AES_128_CCM           (0xC09C, "RSA",   "RSA",  "AES-128/CCM",   16, 4, "AEAD", 0, "SHA-256");
        #/ RSA_WITH_AES_256_CCM           (0xC09D, "RSA",   "RSA",  "AES-256/CCM",   32, 4, "AEAD", 0, "SHA-256");
        #/ DHE_RSA_WITH_AES_128_CCM       (0xC09E, "RSA",   "DH",   "AES-128/CCM",   16, 4, "AEAD", 0, "SHA-256");
        #/ DHE_RSA_WITH_AES_256_CCM       (0xC09F, "RSA",   "DH",   "AES-256/CCM",   32, 4, "AEAD", 0, "SHA-256");
        #/ PSK_WITH_AES_128_CCM           (0xC0A5, "",      "PSK",  "AES-256/CCM",   32, 4, "AEAD", 0, "SHA-256");
        #/ PSK_WITH_AES_256_CCM           (0xC0A4, "",      "PSK",  "AES-128/CCM",   16, 4, "AEAD", 0, "SHA-256");
        #/ ECDHE_ECDSA_WITH_AES_128_CCM   (0xC0AC, "ECDSA", "ECDH", "AES-128/CCM",   16, 4, "AEAD", 0, "SHA-256");
        #/ ECDHE_ECDSA_WITH_AES_256_CCM   (0xC0AD, "ECDSA", "ECDH", "AES-256/CCM",   32, 4, "AEAD", 0, "SHA-256");
        #/ RSA_WITH_AES_128_CCM_8         (0xC0A0, "RSA",   "RSA",  "AES-128/CCM-8", 16, 4, "AEAD", 0, "SHA-256");
        #/ RSA_WITH_AES_256_CCM_8         (0xC0A1, "RSA",   "RSA",  "AES-256/CCM-8", 32, 4, "AEAD", 0, "SHA-256");
        #/ DHE_RSA_WITH_AES_128_CCM_8     (0xC0A2, "RSA",   "DH",   "AES-128/CCM-8", 16, 4, "AEAD", 0, "SHA-256");
        #/ DHE_RSA_WITH_AES_256_CCM_8     (0xC0A3, "RSA",   "DH",   "AES-256/CCM-8", 32, 4, "AEAD", 0, "SHA-256");
        #/ PSK_WITH_AES_128_CCM_8         (0xC0A8, "",      "PSK",  "AES-128/CCM-8", 16, 4, "AEAD", 0, "SHA-256");
        #/ PSK_WITH_AES_256_CCM_8         (0xC0A9, "",      "PSK",  "AES-256/CCM-8", 32, 4, "AEAD", 0, "SHA-256");
        #/ ECDHE_ECDSA_WITH_AES_128_CCM_8 (0xC0AE, "ECDSA", "ECDH", "AES-128/CCM-8", 16, 4, "AEAD", 0, "SHA-256");
        #/ ECDHE_ECDSA_WITH_AES_256_CCM_8 (0xC0AF, "ECDSA", "ECDH", "AES-256/CCM-8", 32, 4, "AEAD", 0, "SHA-256");
        #-------------------------------------+------+-----+------+---+------+-----+--------+----+--------,
        # from openssl-1.0.1g
        'KRB5-DES-CBC3-MD5'             => [qw(  weak SSLv3 3DES   168 MD5    KRB5  KRB5        0 :)],
        'KRB5-DES-CBC3-SHA'             => [qw(  weak SSLv3 3DES   168 SHA1   KRB5  KRB5        0 :)],
        'KRB5-IDEA-CBC-MD5'             => [qw(  weak SSLv3 IDEA   128 MD5    KRB5  KRB5        0 :)],
        'KRB5-IDEA-CBC-SHA'             => [qw(  weak SSLv3 IDEA   128 SHA1   KRB5  KRB5        0 :)],
        'KRB5-RC4-MD5'                  => [qw(  weak SSLv3 RC4    128 MD5    KRB5  KRB5        0 :)],
        'KRB5-RC4-SHA'                  => [qw(  weak SSLv3 RC4    128 SHA1   KRB5  KRB5        0 :)],
        'KRB5-DES-CBC-MD5'              => [qw(  weak SSLv3 DES     56 MD5    KRB5  KRB5        0 :)],
        'KRB5-DES-CBC-SHA'              => [qw(  weak SSLv3 DES     56 SHA1   KRB5  KRB5        0 :)],
        'EXP-KRB5-DES-CBC-MD5'          => [qw(  weak SSLv3 DES     40 MD5    KRB5  KRB5        0 export)],
        'EXP-KRB5-DES-CBC-SHA'          => [qw(  weak SSLv3 DES     40 SHA1   KRB5  KRB5        0 export)],
        'EXP-KRB5-RC2-CBC-MD5'          => [qw(  weak SSLv3 RC2     40 MD5    KRB5  KRB5        0 export)],
        'EXP-KRB5-RC2-CBC-SHA'          => [qw(  weak SSLv3 RC2     40 SHA1   KRB5  KRB5        0 export)],
        'EXP-KRB5-RC4-MD5'              => [qw(  WEAK SSLv3 RC4     40 MD5    KRB5  KRB5        0 export)],
        'EXP-KRB5-RC4-SHA'              => [qw(  WEAK SSLv3 RC4     40 SHA1   KRB5  KRB5        0 export)],
        # from ssl/s3_lib.c
        'FZA-NULL-SHA'                  => [qw(  weak SSLv3 None     0 SHA1   KEA   FZA        11 :)],
        'FZA-FZA-SHA'                   => [qw(MEDIUM SSLv3 FZA      0 SHA1   KEA   FZA        81 :)],
        'FZA-RC4-SHA'                   => [qw(  WEAK SSLv3 RC4    128 SHA1   KEA   FZA        11 :)],
        'RSA-FIPS-3DES-EDE-SHA'         => [qw(  weak SSLv3 3DES   168 SHA1 RSA_FIPS RSA_FIPS   0 :)],
        'RSA-FIPS-3DES-EDE-SHA'         => [qw(  weak SSLv3 3DES   168 SHA1 RSA_FIPS RSA_FIPS   0 :)],
        'RSA-FIPS-DES-CBC-SHA'          => [qw(  weak SSLv3 DES_CBC 56 SHA1 RSA_FIPS RSA_FIPS   0 :)],
        'RSA-FIPS-DES-CBC-SHA'          => [qw(  weak SSLv3 DES_CBC 56 SHA1 RSA_FIPS RSA_FIPS   0 :)],

        'EXP-DH-DSS-DES-CBC-SHA'        => [qw(  weak SSLv3 DES    40 SHA1    DSS   DH(512)     0 export)],
        'EXP-DH-RSA-DES-CBC-SHA'        => [qw(  weak SSLv3 DES    40 SHA1    RSA   DH(512)     0 export)],

        # FIXME: all following
        'DH-DSS-DES-CBC-SHA'            => [qw( weak  SSLv3 DES    56 SHA1    DSS   DH          0 :)],
        'DH-RSA-DES-CBC-SHA'            => [qw( weak  SSLv3 DES    56 SHA1    RSA   DH          0 :)],
        'DH-DSS-DES-CBC3-SHA'           => [qw( weak  SSLv3 3DES   168 SHA1   DSS   DH          0 :)],
        'DH-RSA-DES-CBC3-SHA'           => [qw( weak  SSLv3 3DES   168 SHA1   RSA   DH          0 :)],
        'DH-DSS-AES128-SHA256'          => [qw( high TLSv12 AES    128 SHA256 DSS   DH         91 :)],
        'DH-RSA-AES128-SHA256'          => [qw( high TLSv12 AES    128 SHA256 RSA   DH         91 :)],
        'DH-DSS-AES256-SHA256'          => [qw( high TLSv12 AES    256 SHA256 DSS   DH         91 :)],
        'DH-RSA-AES256-SHA256'          => [qw( high TLSv12 AES    256 SHA256 RSA   DH         91 :)],
        'DH-DSS-SEED-SHA'               => [qw(medium SSLv3 SEED   128 SHA1   DSS   DH         81 :)],
        'DH-RSA-SEED-SHA'               => [qw(medium SSLv3 SEED   128 SHA1   RSA   DH         81 :)],
        'DH-RSA-AES128-GCM-SHA256'      => [qw( high TLSv12 AESGCM 128 AEAD   RSA   DH         91 :)],
        'DH-RSA-AES256-GCM-SHA384'      => [qw( high TLSv12 AESGCM 256 AEAD   RSA   DH         91 :)],
        'DH-DSS-AES128-GCM-SHA256'      => [qw( high TLSv12 AESGCM 128 AEAD   DSS   DH         91 :)],
        'DH-DSS-AES256-GCM-SHA384'      => [qw( high TLSv12 AESGCM 256 AEAD   DSS   DH         91 :)],
        'DHE-PSK-SHA'                   => [qw( weak TLSv12 None   0   SHA1   PSK   DHE         1 :)],
        'RSA-PSK-SHA'                   => [qw( weak TLSv12 None   0   SHA1   PSK   RSA         1 :)],
        'DHE-PSK-RC4-SHA'               => [qw(medium TLSv12 RC4   128 SHA1   PSK   DHE         1 :)],
        'DHE-PSK-3DES-SHA'              => [qw( weak TLSv12 3DES   168 SHA1   PSK   DHE         0 :)],
        'DHE-PSK-AES128-SHA'            => [qw(  -?- TLSv12 AES    128 SHA1   PSK   DHE         1 :)],
        'DHE-PSK-AES256-SHA'            => [qw(  -?- TLSv12 AES    256 SHA1   PSK   DHE         1 :)],
        'DHE-PSK-AES128-GCM-SHA256'     => [qw(  -?- TLSv12 AES    128 SHA256 PSK   DHE         1 :)],
        'DHE-PSK-AES256-GCM-SHA384'     => [qw(  -?- TLSv12 AES    256 SHA384 PSK   DHE         1 :)],
        'RSA-PSK-AES128-GCM-SHA256'     => [qw(  -?- TLSv12 AES    128 SHA256 PSK   RSA         1 :)],
        'RSA-PSK-AES256-GCM-SHA384'     => [qw(  -?- TLSv12 AES    256 SHA384 PSK   RSA         1 :)],
        'PSK-AES128-SHA256'             => [qw(  -?- TLSv12 AES    128 SHA256 PSK   PSK         1 :)],
        'PSK-AES256-SHA384'             => [qw(  -?- TLSv12 AES    256 SHA384 PSK   PSK         1 :)],
        'PSK-SHA256'                    => [qw( weak TLSv12 None   0   SHA256 PSK   PSK         1 :)],
        'PSK-SHA384'                    => [qw( weak TLSv12 None   0   SHA384 PSK   PSK         1 :)],
        'DHE-PSK-AES128-SHA256'         => [qw(  -?- TLSv12 AES    128 SHA256 PSK   DHE         1 :)],
        'DHE-PSK-AES256-SHA384'         => [qw(  -?- TLSv12 AES    256 SHA384 PSK   DHE         1 :)],
        'DHE-PSK-SHA256'                => [qw( weak TLSv12 None   0   SHA256 PSK   DHE         1 :)],
        'DHE-PSK-SHA384'                => [qw( weak TLSv12 None   0   SHA384 PSK   DHE         1 :)],
        'RSA-PSK-AES128-SHA256'         => [qw(  -?- TLSv12 AES    128 SHA256 PSK   RSA         1 :)],
        'RSA-PSK-AES256-SHA384'         => [qw(  -?- TLSv12 AES    256 SHA384 PSK   RSA         1 :)],
        'RSA-PSK-SHA256'                => [qw(  -?- TLSv12 AES    0   SHA256 PSK   RSA         1 :)],
        'RSA-PSK-SHA384'                => [qw(  -?- TLSv12 AES    0   SHA384 PSK   RSA         1 :)],

        # from http://tools.ietf.org/html/rfc6209
        #!# 'head'                      => [qw(  sec  ssl   enc   bits   mac    auth  keyx    score tags)],
        #!#-----------------------------------+------+-----+------+-----+------+-----+--------+----+--------,
        'RSA-ARIA128-SHA256'            => [qw(  -?- TLSv12 ARIA     128 SHA256 RSA   RSA     11 :)],
        'RSA-ARIA256-SHA384'            => [qw(  -?- TLSv12 ARIA     256 SHA384 RSA   RSA     11 :)],
        'DH_DSS-ARIA128-SHA256'         => [qw(  -?- TLSv12 ARIA     128 SHA256 DSS   DH      11 :)],
        'DH_DSS-ARIA256-SHA384'         => [qw(  -?- TLSv12 ARIA     256 SHA384 DSS   DH      11 :)],
        'DH_RSA-ARIA128-SHA256'         => [qw(  -?- TLSv12 ARIA     128 SHA256 RSA   DH      11 :)],
        'DH_RSA-ARIA256-SHA384'         => [qw(  -?- TLSv12 ARIA     256 SHA384 RSA   DH      11 :)],
        'DHE_DSS-ARIA128-SHA256'        => [qw(  -?- TLSv12 ARIA     128 SHA256 DSS   DHE     11 :)], # unklar
        'DHE_DSS-ARIA256-SHA384'        => [qw(  -?- TLSv12 ARIA     256 SHA384 DSS   DHE     11 :)], # unklar
        'DHE_RSA-ARIA128-SHA256'        => [qw(  -?- TLSv12 ARIA     128 SHA256 RSA   DHE     11 :)], # unklar
        'DHE_RSA-ARIA256-SHA384'        => [qw(  -?- TLSv12 ARIA     256 SHA384 RSA   DHE     11 :)], # unklar
        'ADH-ARIA128-SHA256'            => [qw(  -?- TLSv12 ARIA     128 SHA256 None  DH      11 :)], # unklar
        'ADH-ARIA256-SHA384'            => [qw(  -?- TLSv12 ARIA     256 SHA384 None  DH      11 :)], # unklar
        'ECDHE_ECDSA-ARIA128-SHA256'    => [qw(  -?- TLSv12 ARIA     128 SHA256 ECDSA ECDHE   11 :)],
        'ECDHE_ECDSA-ARIA256-SHA384'    => [qw(  -?- TLSv12 ARIA     256 SHA384 ECDSA ECDHE   11 :)],
        'ECDH_ECDSA-ARIA128-SHA256'     => [qw(  -?- TLSv12 ARIA     128 SHA256 ECDSA ECDH    11 :)],
        'ECDH_ECDSA-ARIA256-SHA384'     => [qw(  -?- TLSv12 ARIA     256 SHA384 ECDSA ECDH    11 :)],
        'ECDHE_RSA-ARIA128-SHA256'      => [qw(  -?- TLSv12 ARIA     128 SHA256 RSA   ECDHE   11 :)],
        'ECDHE_RSA-ARIA256-SHA384'      => [qw(  -?- TLSv12 ARIA     256 SHA384 RSA   ECDHE   11 :)],
        'ECDH_RSA-ARIA128-SHA256'       => [qw(  -?- TLSv12 ARIA     128 SHA256 RSA   ECDH    11 :)],
        'ECDH_RSA-ARIA256-SHA384'       => [qw(  -?- TLSv12 ARIA     256 SHA384 RSA   ECDH    11 :)],
        'RSA-ARIA128-GCM-SHA256'        => [qw(  -?- TLSv12 ARIAGCM  128 SHA256 RSA   RSA     11 :)],
        'RSA-ARIA256-GCM-SHA384'        => [qw(  -?- TLSv12 ARIAGCM  256 SHA384 RSA   RSA     11 :)],
        'DHE_RSA-ARIA128-GCM-SHA256'    => [qw(  -?- TLSv12 ARIAGCM  128 SHA256 RSA   DHE     11 :)], # unklar
        'DHE_RSA-ARIA256-GCM-SHA384'    => [qw(  -?- TLSv12 ARIAGCM  256 SHA384 RSA   DHE     11 :)], # unklar
        'DH_RSA-ARIA128-GCM-SHA256'     => [qw(  -?- TLSv12 ARIAGCM  128 SHA256 RSA   DH      11 :)],
        'DH_RSA-ARIA256-GCM-SHA384'     => [qw(  -?- TLSv12 ARIAGCM  256 SHA384 RSA   DH      11 :)],
        'DHE_DSS-ARIA128-GCM-SHA256'    => [qw(  -?- TLSv12 ARIAGCM  128 SHA256 DSS   DHE     11 :)], # unklar
        'DHE_DSS-ARIA256-GCM-SHA384'    => [qw(  -?- TLSv12 ARIAGCM  256 SHA384 DSS   DHE     11 :)], # unklar
        'DH_DSS-ARIA128-GCM-SHA256'     => [qw(  -?- TLSv12 ARIAGCM  128 SHA256 DSS   DH      11 :)],
        'DH_DSS-ARIA256-GCM-SHA384'     => [qw(  -?- TLSv12 ARIAGCM  256 SHA384 DSS   DH      11 :)],
        'ADH-ARIA128-GCM-SHA256'        => [qw(  -?- TLSv12 ARIAGCM  128 SHA256 None  DH      11 :)],
        'ADH-ARIA256-GCM-SHA384'        => [qw(  -?- TLSv12 ARIAGCM  256 SHA384 None  DH      11 :)],
        'ECDHE_ECDSA-ARIA128-GCM-SHA256'=> [qw(  -?- TLSv12 ARIAGCM  128 SHA256 ECDSA ECDHE   11 :)],
        'ECDHE_ECDSA-ARIA256-GCM-SHA384'=> [qw(  -?- TLSv12 ARIAGCM  256 SHA384 ECDSA ECDHE   11 :)],
        'ECDH_ECDSA-ARIA128-GCM-SHA256' => [qw(  -?- TLSv12 ARIAGCM  128 SHA256 ECDSA ECDH    11 :)],
        'ECDH_ECDSA-ARIA256-GCM-SHA384' => [qw(  -?- TLSv12 ARIAGCM  256 SHA384 ECDSA ECDH    11 :)],
        'ECDHE_RSA-ARIA128-GCM-SHA256'  => [qw(  -?- TLSv12 ARIAGCM  128 SHA256 RSA   ECDHE   11 :)],
        'ECDHE_RSA-ARIA256-GCM-SHA384'  => [qw(  -?- TLSv12 ARIAGCM  256 SHA384 RSA   ECDHE   11 :)],
        'ECDH_RSA-ARIA128-GCM-SHA256'   => [qw(  -?- TLSv12 ARIAGCM  128 SHA256 RSA   ECDH    11 :)],
        'ECDH_RSA-ARIA256-GCM-SHA384'   => [qw(  -?- TLSv12 ARIAGCM  256 SHA384 RSA   ECDH    11 :)],
        'PSK-ARIA128-SHA256'            => [qw(  -?- TLSv12 ARIA     128 SHA256 PSK   PSK     11 :)],
        'PSK-ARIA256-SHA384'            => [qw(  -?- TLSv12 ARIA     256 SHA384 PSK   PSK     11 :)],
        'DHE_PSK-ARIA128-SHA256'        => [qw(  -?- TLSv12 ARIA     128 SHA256 PSK   DHE     11 :)], # unklar
        'DHE_PSK-ARIA256-SHA384'        => [qw(  -?- TLSv12 ARIA     256 SHA384 PSK   DHE     11 :)], # unklar
        'RSA_PSK-ARIA128-SHA256'        => [qw(  -?- TLSv12 ARIA     128 SHA256 PSK   RSA     11 :)],
        'RSA_PSK-ARIA256-SHA384'        => [qw(  -?- TLSv12 ARIA     256 SHA384 PSK   RSA     11 :)],
        'PSK-ARIA128-GCM-SHA256'        => [qw(  -?- TLSv12 ARIAGCM  128 SHA256 PSK   PSK     11 :)],
        'PSK-ARIA256-GCM-SHA384'        => [qw(  -?- TLSv12 ARIAGCM  256 SHA384 PSK   PSK     11 :)],
        'DHE_PSK-ARIA128-GCM-SHA256'    => [qw(  -?- TLSv12 ARIAGCM  128 SHA256 PSK   DHE     11 :)], # unklar
        'DHE_PSK-ARIA256-GCM-SHA384'    => [qw(  -?- TLSv12 ARIAGCM  256 SHA384 PSK   DHE     11 :)], # unklar
        'RSA_PSK-ARIA128-GCM-SHA256'    => [qw(  -?- TLSv12 ARIAGCM  128 SHA256 PSK   RSA     11 :)],
        'RSA_PSK-ARIA256-GCM-SHA384'    => [qw(  -?- TLSv12 ARIAGCM  256 SHA384 PSK   RSA     11 :)],
        'ECDHE_PSK-ARIA128-SHA256'      => [qw(  -?- TLSv12 ARIA     128 SHA256 PSK   ECDHE   11 :)],

        # from: https://chromium.googlesource.com/chromium/src/net/+/master/ssl/ssl_cipher_suite_names_unittest.cc
        'CECPQ1-RSA-CHACHA20-POLY1305-SHA256'   => [qw( HIGH TLSv12 ChaCha20-Poly1305 256 SHA256 RSA   CECPQ1 91 :)],
        'CECPQ1-ECDSA-CHACHA20-POLY1305-SHA256' => [qw( HIGH TLSv12 ChaCha20-Poly1305 256 SHA256 ECDSA CECPQ1 91 :)],
        'CECPQ1-RSA-AES256-GCM-SHA384'          => [qw( HIGH TLSv12 AESGCM 256 SHA384 RSA   CECPQ1 91 :)],
        'CECPQ1-ECDSA-AES256-GCM-SHA384'        => [qw( HIGH TLSv12 AESGCM 256 SHA384 ECDSA CECPQ1 91 :)],

    # === openssl ===
    # most of above table (roughly) generated with:
    #   openssl ciphers -v ALL:eNULL:aNULL | sort \
    #   | awk '{e=$7;printf("\t%26s => [%s, %s, %s, %s, %s, %s, %s],\n",$1,$2,substr($5,5),substr($5,index($5,"(")+1),substr($6,5),substr($4,4),substr($3,4),e)}'
    # or better
    #   | awk '{q="'"'"'";a=sprintf("%s%c",$1,q);e=$7;printf("\t%c%-26s => [qw( -?-\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t13 :)],\n",q,a,$2,substr($5,5),substr($5,index($5,"(")+1),substr($6,5),substr($4,4),substr($3,4),e)}' # )
    # === openssl 0.9.8o ===
    # most of above table (roughly) generated with:
    #   openssl ciphers -v ALL:eNULL:aNULL | sort
    #
    # NOTE: some openssl (0.9.8o on Ubuntu 11.10) fail to list ciphers with
    #    openssl ciphers -ssl2 -v

); # %ciphers

our %text = (
    'separator'     => ":",# separator character between label and value
    # texts may be redefined
    'undef'         => "<<undefined>>",
    'response'      => "<<response>>",
    'protocol'      => "<<protocol probably supported, but no ciphers accepted>>",
    'need_cipher'   => "<<check possible in conjunction with +cipher only>>",
    'na'            => "<<N/A>>",
    'na_STS'        => "<<N/A as STS not set>>",
    'na_dns'        => "<<N/A as --no-dns in use>>",
    'na_cert'       => "<<N/A as --no-cert in use>>",
    'na_http'       => "<<N/A as --no-http in use>>",
    'na_tlsextdebug'=> "<<N/A as --no-tlsextdebug in use>>",
    'na_nextprotoneg'=>"<<N/A as --no-nextprotoneg in use>>",
    'na_reconnect'  => "<<N/A as --na_reconnect in use>>",
    'na_openssl'    => "<<N/A as --no-openssl in use>>",
    'disabled'      => "<<N/A as @@ in use>>",     # @@ is --no-SSLv2 or --no-SSLv3
    'disabled_protocol' => "<<N/A as protocol disabled or NOT YET implemented>>",     # @@ is --no-SSLv2 or --no-SSLv3
    'disabled_test' => "tests with/for @@ disabled",  # not yet used
    'miss_cipher'   => "<<N/A as no ciphers found>>",
    'miss_RSA'      => " <<missing ECDHE-RSA-* cipher>>",
    'miss_ECDSA'    => " <<missing ECDHE-ECDSA-* cipher>>",
    'missing'       => " <<missing @@>>",
    'enabled_extension' => " <<@@ extension enabled>>",
    'insecure'      => " <<insecure @@>>",
    'invalid'       => " <<invalid @@>>",
    'bit256'        => " <<keysize @@ < 256>>",
    'bit512'        => " <<keysize @@ < 512>>",
    'bit2048'       => " <<keysize @@ < 2048>>",
    'bit4096'       => " <<keysize @@ < 4096>>",
    'EV_large'      => " <<too large @@>>",
    'EV_subject_CN' => " <<missmatch: subject CN= and commonName>>",
    'EV_subject_host'=>" <<missmatch: subject CN= and given hostname>>",
    'no_reneg'      => " <<secure renegotiation not supported>>",
    'cert_dates'    => " <<invalid certificate date>>",
    'cert_valid'    => " <<certificate validity to large @@>>",
    'cert_chars'    => " <<invalid charcters in @@>>",
    'wildcards'     => " <<uses wildcards:@@>>",
    'gethost'       => " <<gethostbyaddr() failed>>",
    'out_target'    => "\n==== Target: @@ ====\n",
    'out_ciphers'   => "\n=== Ciphers: Checking @@ ===",
    'out_infos'     => "\n=== Informations ===",
    'out_scoring'   => "\n=== Scoring Results EXPERIMENTAL ===",
    'out_checks'    => "\n=== Performed Checks ===",
    'out_list'      => "=== List @@ Ciphers ===",
    'out_summary'   => "=== Ciphers: Summary @@ ==",
    # hostname texts
    'host_name'     => "Given hostname",
    'host_IP'       => "IP for given hostname",
    'host_rhost'    => "Reverse resolved hostname",
    'host_DNS'      => "DNS entries for given hostname",
    # misc texts
    'cipher'        => "Cipher",
    'support'       => "supported",
    'security'      => "Security",
    'dh_param'      => "DH Parameters",
    'desc'          => "Description",
    'desc_check'    => "Check Result (yes is considered good)",
    'desc_info'     => "Value",
    'desc_score'    => "Score (max value 100)",

    # texts used for legacy mode; DO NOT CHANGE!
    'legacy' => {      #--------------+------------------------+---------------------
        #header     => # not implemented  supported               unsupported
        #              #----------------+------------------------+---------------------
        'compact'   => { 'not' => '-',   'yes' => "yes",         'no' => "no" },
        'simple'    => { 'not' => '-?-', 'yes' => "yes",         'no' => "no" },
        'full'      => { 'not' => '-?-', 'yes' => "Yes",         'no' => "No" },
        'key'       => { 'not' => '-?-', 'yes' => "yes",         'no' => "no" },
        #              #----------------+------------------------+---------------------
        # following keys are roughly the names of the tool they are used
        #              #----------------+------------------------+---------------------
        'sslaudit'  => { 'not' => '-?-', 'yes' => "successfull", 'no' => "unsuccessfull" },
        'sslcipher' => { 'not' => '-?-', 'yes' => "ENABLED",     'no' => "DISABLED"  },
        'ssldiagnos'=> { 'not' => '-?-', 'yes' => "CONNECT_OK CERT_OK", 'no' => "FAILED" },
        'sslscan'   => { 'not' => '-?-', 'yes' => "Accepted",    'no' => "Rejected"  },
        'ssltest'   => { 'not' => '-?-', 'yes' => "Enabled",     'no' => "Disabled"  },
        'ssltest-g' => { 'not' => '-?-', 'yes' => "Enabled",     'no' => "Disabled"  },
        'sslyze'    => { 'not' => '-?-', 'yes' => "%s",          'no' => "SSL Alert" },
        'testsslserver'=>{'not'=> '-?-', 'yes' => "",            'no' => ""          },
        'thcsslcheck'=>{ 'not' => '-?-', 'yes' => "supported",   'no' => "unsupported"   },

        #              #----------------+------------------------+---------------------
        #                -?- means "not implemented"
        # all other text used in headers titles, etc. are defined in the
        # corresponding print functions:
        #     printtitle, print_cipherhead, printfooter, print_cipherprefered, print_ciphertotals
    },
    # NOTE: all other legacy texts are hardcoded, as there is no need to change them!

    # Texts used for hints, key must be same as a command (without leading +)
    # Currently we define the hints here,  but it can be done anywhere in the
    # code, which may be useful for documentation purpose  because such hints
    # often describe missing features or functionality.
    # TODO: move this to %cfg{hints}
    'hints' => {
        'renegotiation' => "checks only if renegotiation is implemented serverside according RFC5746 ",
        'drown'     => "checks only if the target server itself is vulnerable to DROWN ",
        'robot'     => "checks only if the target offers ciphers vulnerable to ROBOT ",
    },

    'mnemonic'      => { # NOT YET USED
        'example'   => "TLS_DHE_DSS_WITH_3DES-EDE-CBC_SHA",
        'description'=> "TLS Version _ key establishment algorithm _ digital signature algorithm _ WITH _ confidentility algorithm _ hash function",
        'explain'   => "TLS Version1 _ Ephemeral DH key agreement _ DSS which implies DSA _ WITH _ 3DES encryption in CBC mode _ SHA for HMAC"
    },

    # just for information, some configuration options in Firefox
    'firefox' => { # NOT YET USED
        'browser.cache.disk_cache_ssl'        => "En-/Disable caching of SSL pages",        # false
        'security.enable_tls_session_tickets' => "En-/Disable Session Ticket extension",    # false
        'security.ssl.allow_unrestricted_renego_everywhere__temporarily_available_pref' =>"",# false
        'security.ssl.renego_unrestricted_hosts' => '??', # Liste
        'security.ssl.require_safe_negotiation'  => "",   # true
        'security.ssl.treat_unsafe_negotiation_as_broken' => "", # true
        'security.ssl.warn_missing_rfc5746'      => "",   # true
        'pfs.datasource.url' => '??', #
        'browser.identity.ssl_domain_display'    => "coloured non EV-SSL Certificates", # true
        },
    'IE' => { # NOT YET USED
        'HKLM\\...' => "sequence of ciphers", #
        },

    # for more informations about definitions and RFC, see o-saft-man.pm

); # %text

$cmd{'extopenssl'}  = 0 if ($^O =~ m/MSWin32/); # tooooo slow on Windows
$cmd{'extsclient'}  = 0 if ($^O =~ m/MSWin32/); # tooooo slow on Windows
$cfg{'done'}->{'rc-file'}++ if ($#rc_argv > 0);

#| incorporate some environment variables
#| -------------------------------------
# all OPENSSL* environment variables are checked and assigned in o-saft-lib.pm
$cmd{'openssl'}     = $cfg{'openssl_env'} if (defined $cfg{'openssl_env'});
if (defined $ENV{'LIBPATH'}) {
    _hint("LIBPATH environment variable found, consider using '--envlibvar=LIBPATH'");
    # TODO: avoid hint if --envlibvar=LIBPATH in use
    # $cmd{'envlibvar'} = $ENV{'LIBPATH'}; # don't set silently
}

#_init_all();  # call delayed to prevent warning of prototype check with -w

_yeast_EXIT("exit=INIT1 - initialization end");
usr_pre_file();

#| definitions: internal functions
#| -------------------------------------
sub _isnummber          {
    # return 1 if given parameter is a number; return 0 otherwise
    my $val = shift;
    return 0 if not defined $val;
    return 0 if $val eq '';
    return ($val ^ $val) ? 0 : 1
}

use IO::Socket::INET;
sub _load_modules       {
    # load required modules
    # SEE Perl:import include
    my $txt = "";
    if (1 > 0) { # TODO: experimental code
        $txt = _load_file("IO/Socket/SSL.pm", "IO SSL module");
        warn STR_ERROR, "004: $txt" if ($txt ne "");
        # cannot load IO::Socket::INET delayed because we use AF_INET,
        # otherwise we get at startup:
        #    Bareword "AF_INET" not allowed while "strict subs" in use ...
        #$txt = _load_file("IO/Socket/INET.pm", "IO INET module");
        #warn STR_ERROR, "005: $txt" if ($txt ne "");
    }
    if ($cfg{'need_netdns'} > 0) {
        $txt = _load_file("Net/DNS.pm", "Net module");
        if ($txt ne "") {
            warn STR_ERROR, "006: $txt";
            _warn("111: option --mx disabled");
            $cfg{'usemx'} = 0;
        }
    }
    if ($cfg{'need_timelocal'} > 0) {
        $txt = _load_file("Time/Local.pm", "Time module");
        if ($txt ne "") {
            warn STR_ERROR, "007: $txt";
            _warn("112: value for +sts_expired not applicable");
            # TODO: need to remove +sts_expired from cfg{do}
        }
    }

    return if ($osaft_standalone > 0);  # SEE Note:Stand-alone

    if (_is_do('cipherraw') or _is_do('version')
        or ($cfg{'starttls'})
        or (($cfg{'proxyhost'}) and ($cfg{'proxyport'}))
       ) {
        $txt = _load_file("Net/SSLhello.pm", "O-Saft module");  # must be found with @INC
        if ($txt ne "") {
            die  STR_ERROR, "008: $txt"  if (not _is_do('version'));
            warn STR_ERROR, "008: $txt";# no reason to die for +version
        }
        $cfg{'usehttp'} = 0;            # makes no sense for starttls
        # TODO: not (yet) supported for proxy
    }
    $txt = _load_file("Net/SSLinfo.pm", "O-Saft module");       # must be found
    if ($txt ne "") {
        die  STR_ERROR, "009: $txt"  if (not _is_do('version'));
        warn STR_ERROR, "009: $txt";    # no reason to die for +version
    }
    return;
} # _load_modules

sub _check_modules      {
    # check for minimal version of a module;
    # verbose output with --v=2 ; uses string "yes" for contrib/bunt.*
    # these checks print warnings with warn() not _warn(), SEE Perl:warn
    # SEE Perl:import include
    _y_CMD("  check module versions ...");
    my %expected_versions = (
        'IO::Socket::INET'  => "1.31",
        'IO::Socket::SSL'   => "1.37",
        'Net::SSLeay'       => "1.49",
        'Net::DNS'          => "0.65",
        'Time::Local'       => "1.23",
        # to simulate various error conditions, simply modify the module name
        # and/or its expected version in above table;  these values are never
        # used elsewhere
    );
    # Comparing version numbers is tricky, 'cause they are no natural numbers
    # Consider for example 1.8 and 1.11 : where the numerical comapre returns
    #   "1.8 > 1.11".
    # Perl has the version module for this, but it's available for Perl > 5.9
    # only. For older Perl, we warn that version checks may not be accurate.
    # Please see "perldoc version" about the logic and syntax.
    my $have_version = 1;
    eval {require version; } or $have_version = 0;
        # $version::VERSION  may have one of 3 values now:
        #   undef   - version module was not available or didn't define VERSION
        #   string  - even "0.42" cannot be compared to integer, bad luck ...
        #   integer - that's the usual and expected value
    if (_isnummber($version::VERSION) == 1) {
        $have_version = 0 if ($version::VERSION < 0.77);
            # veriosn module too old, use natural number compare
    } else {
        $have_version = 0;
        $version::VERSION = ""; # defensive programming ..
    }
    if ($have_version == 0) {
        warn STR_WARN, "120: ancient perl has no 'version' module; version checks may not be accurate;";
    }
    if ($cfg{verbose} > 1) {
        printf "# %s+%s+%s\n", "-"x21, "-"x7, "-"x15;
        printf "# %-21s\t%s\t%s\n", "module name", "VERSION", "> expected versions";
        printf "# %s+%s+%s\n", "-"x21, "-"x7, "-"x15;
    }
    foreach my $mod (keys %expected_versions) {
        next if (($cfg{'need_netdns'}    == 0) and ($mod eq "Net::DNS"));# don't complain if not used
        next if (($cfg{'need_timelocal'} == 0) and ($mod eq "Time::Local"));# -"-
        no strict 'refs'; ## no critic qw(TestingAndDebugging::ProhibitNoStrict TestingAndDebugging::ProhibitProlongedStrictureOverride)
            # avoid: Can't use string ("Net::DNS::VERSION") as a SCALAR ref while "strict refs" in use
        my $expect = $expected_versions{$mod};
        my $v  = $mod . "::VERSION";
        my $ok = "yes";
        # following eval is safe, as left side value cannot be injected
        eval {$v = $$v;} or $v = 0;     # module was not loaded or has no VERSION
        if ($have_version == 1) {       # accurate checks with version module
            # convert natural numbers to version objects
            $v      = version->parse("v$v");
            $expect = version->parse("v$expect");
        }
        if ($v < $expect) {
            $ok = "no";
            $ok = "missing" if ($v == 0);
            warn STR_WARN, "121: ancient $mod $v < $expect detected;";
            # TODO: not sexy: warnings are inside tabular data for --v
        }
        if ($cfg{verbose} > 1) {
            printf "# %-21s\t%s\t> %s\t%s\n", $mod, $v, $expect, $ok;
        }
    }
    printf "# %s+%s+%s\n", "-"x21, "-"x7, "-"x15 if ($cfg{verbose} > 1);
    return;
} # _check_modules

sub _enable_functions   {
    # enable internal functionality based on available functionality of modules
    # these checks print warnings with warn() not _warn(), SEE Perl:warn
    # verbose messages with --v --v
    # Note: don't bother users with warnings, if functionality is not required
    #       hence some additional checks around the warnings
    # Note: instead of requiring a specific version with Perl's use,  only the
    #       version of the loaded module is checked; this allows continuing to
    #       use this tool even if the version is too old; but  shout  out loud
    my $version_openssl  = shift;
    my $version_ssleay   = shift;
    my $version_iosocket = shift;
    my $txo = sprintf("ancient openssl version 0x%x", $version_openssl);
    my $txs = "ancient version Net::SSLeay $version_ssleay";
    my $txi = "ancient version IO::Socket::SSL $version_iosocket";
    my $txt = "improper Net::SSLeay version;";

    _y_CMD("  enable internal functionality ...");

    if ($cfg{'ssleay'}->{'openssl'} == 0) {
        warn STR_WARN, "122: ancient Net::SSLeay $version_ssleay cannot detect openssl version";
    }
    if ($cfg{'ssleay'}->{'iosocket'} == 0) {
        warn STR_WARN, "123: ancient or unknown version of IO::Socket detected";
    }

    if ($cfg{'ssleay'}->{'can_sni'} == 0) {
        if(($cfg{'usesni'} > 0) and ($cmd{'extciphers'} == 0)) {
            $cfg{'usesni'} = 0;
            if ($version_iosocket < 1.90) {
                warn STR_WARN, "124: $txi < 1.90; does not support SNI or is known to be buggy; SNI disabled;";
            }
            if ($version_openssl  < 0x01000000) {
                warn STR_WARN, "125: $txo < 1.0.0; does not support SNI or is known to be buggy; SNI disabled;";
            }
            _hint("--force-openssl can be used to disable this check");
        }
    }
    _trace(" cfg{usesni}: $cfg{'usesni'}");

    if (($cfg{'ssleay'}->{'set_alpn'} == 0) or ($cfg{'ssleay'}->{'get_alpn'} == 0)) {
        # warnings only if ALPN functionality required
        # TODO: is this check necessary if ($cmd{'extciphers'} > 0)?
        if ($cfg{'usealpn'} > 0) {
            $cfg{'usealpn'} = 0;
            warn STR_WARN, "126: $txt tests with/for ALPN disabled";
            if ($version_ssleay   < 1.56) {  # is also < 1.46
                warn STR_WARN, "127: $txs < 1.56"   if ($cfg{'verbose'} > 1);
            }
            if ($version_openssl  < 0x10002000) {
                warn STR_WARN, "128: $txo < 1.0.2"  if ($cfg{'verbose'} > 1);
            }
            _hint("--no-alpn can be used to disable this check");
        }
    }
    _trace(" cfg{usealpn}: $cfg{'usealpn'}");

    if ($cfg{'ssleay'}->{'set_npn'} == 0) {
        # warnings only if NPN functionality required
        if ($cfg{'usenpn'}  > 0) {
            $cfg{'usenpn'}  = 0;
            warn STR_WARN, "129: $txt tests with/for NPN disabled";
            if ($version_ssleay   < 1.46) {
                warn STR_WARN, "130: $txs < 1.46"   if ($cfg{'verbose'} > 1);
            }
            if ($version_openssl  < 0x10001000) {
                warn STR_WARN, "132: $txo < 1.0.1"  if ($cfg{'verbose'} > 1);
            }
            _hint("--no-npn can be used to disable this check");
        }
    }
    _trace(" cfg{usenpn}: $cfg{'usenpn'}");

    if ($cfg{'ssleay'}->{'can_ocsp'} == 0) {
        warn STR_WARN, "133: $txt tests for OCSP disabled";
        #_hint("--no-ocsp  can be used to disable this check");
    }

    if ($cfg{'ssleay'}->{'can_ecdh'} == 0) {
        warn STR_WARN, "134: $txt setting curves disabled";
        #_hint("--no-cipher-ecdh  can be used to disable this check");
    }
    return;
} # _enable_functions

sub _check_functions    {
    # check for required functionality
    # these checks print warnings with warn() not _warn(), SEE Perl:warn
    # verbose messages with --v=2 ; uses string "yes" for contrib/bunt.*

    my $txt = "";
    my $tmp = "";
    my $version_openssl  =  0; # use 0 to avoid 0xffffffffffffffff in warnings
    my $version_ssleay   = -1; # -1 should be always lower than anything else
    my $version_iosocket = -1; # -"-
    my $text_ssleay      = "Net::SSLeay\t$version_ssleay supports";

    # Note: $cfg{'ssleay'}->{'can_sni'} are set to 1 be default, will be

    _y_CMD("  check required modules ...");
    if (not defined $Net::SSLeay::VERSION) {# Net::SSLeay auto-loaded by IO::Socket::SSL
        if ($cmd{'extopenssl'} == 0) {
            die STR_ERROR, "013: Net::SSLeay not found, useless use of SSL advanced forensic tool";
        }
    } else {
        $version_ssleay   = $Net::SSLeay::VERSION;
        $text_ssleay      = "Net::SSLeay\t$version_ssleay supports";
    }
    if (not exists &Net::SSLeay::OPENSSL_VERSION_NUMBER) {
        $cfg{'ssleay'}->{'openssl'} = 0;
    } else {
        $version_openssl  = Net::SSLeay::OPENSSL_VERSION_NUMBER();
    }
    if (not defined $IO::Socket::SSL::VERSION) {
        $cfg{'ssleay'}->{'iosocket'} = 0;
    } else {
        $version_iosocket = $IO::Socket::SSL::VERSION;
    }

    # some functionality is available in  Net::SSLeay  and  IO::Socket::SSL,
    # newer versions of  IO::Socket::SSL  even provides variables for it
    # ancient versions of the modules,  which do not have these functions or
    # variables, should be supported
    # that's why the checks are done here and stored in $cfg{'ssleay'}->*

    _y_CMD("  check for proper SNI support ...");
    if ($version_iosocket < 1.90) {
        $cfg{'ssleay'}->{'can_sni'} = 0;
    } else {
        _v2print "IO::Socket::SSL\t$version_iosocket OK\tyes";
    }
    if ($version_openssl < 0x01000000) {
        # same as  IO::Socket::SSL->can_client_sni()
        # see section "SNI Support" in: perldoc IO/Socket/SSL.pm
        $cfg{'ssleay'}->{'can_sni'} = 0;
    } else {
        _v2print "$text_ssleay OpenSSL version\tyes";
    }

    _y_CMD("  check if Net::SSLeay is usable ...");
    if ($version_ssleay  < 1.49) {
        warn STR_WARN, "135: $txt < 1.49; may throw warnings and/or results may be missing;";
    } else {
        _v2print "$text_ssleay (OK)\tyes";
    }

    _y_CMD("  check for NPN and ALPN support ..."); # SEE Note:OpenSSL Version
    if (($version_ssleay < 1.56) or ($version_openssl < 0x10002000)) {
        $cfg{'ssleay'}->{'set_alpn'} = 0;
        $cfg{'ssleay'}->{'get_alpn'} = 0;
    } else {
        _v2print "$text_ssleay ALPN\tyes";
    }
    if (($version_ssleay < 1.46) or ($version_openssl < 0x10001000)) {
        $cfg{'ssleay'}->{'set_npn'}  = 0;
    } else {
        _v2print "$text_ssleay  NPN\tyes";
    }

    if (not exists &Net::SSLeay::CTX_set_alpn_protos) {
        $cfg{'ssleay'}->{'set_alpn'} = 0;
    } else {
        _v2print "$text_ssleay set ALPN\tyes";
    }

    if (not exists &Net::SSLeay::P_alpn_selected) {
        $cfg{'ssleay'}->{'get_alpn'} = 0;
    } else {
        _v2print "$text_ssleay get ALPN\tyes";
    }

    if (not exists &Net::SSLeay::CTX_set_next_proto_select_cb) {
        $cfg{'ssleay'}->{'set_npn'} = 0;
    } else {
        _v2print "$text_ssleay set  NPN\tyes";
    }

    if (not exists &Net::SSLeay::P_next_proto_negotiated) {
        $cfg{'ssleay'}->{'get_npn'}  = 0;
    } else {
        _v2print "$text_ssleay get  NPN\tyes";
    }

    if (not exists &Net::SSLeay::OCSP_cert2ids) {
        # same as IO::Socket::SSL::can_ocsp() IO::Socket::SSL::can_ocsp_staple()
        $cfg{'ssleay'}->{'can_ocsp'}  = 0;
    } else {
        _v2print "$text_ssleay OSCP\tyes";
    }

    if (not exists &Net::SSLeay::CTX_set_tmp_ecdh) {
        # same as IO::Socket::SSL::can_ecdh()
        $cfg{'ssleay'}->{'can_ecdh'}  = 0;
    } else {
        _v2print "$text_ssleay Curves\tyes";
    }

    $cfg{'ssleay'}->{'can_npn'}  = $cfg{'ssleay'}->{'get_npn'}; # alias
    _enable_functions($version_openssl, $version_ssleay, $version_iosocket);
    return;
} # _check_functions

sub _check_SSL_methods  {
   # check for supported SSL version methods and add them to $cfg{'version'}
   # TODO: anything related to +cipherraw can be removed when Net::SSLhello
   #       supports DTLSv1
    my $typ;
    my @list;
    _y_CMD("  check supported SSL versions ...");
    if (! _is_do('cipherraw')) {        # +cipherraw does not need these checks
        @list = Net::SSLinfo::ssleay_methods();
        # method names do not literally match our version string, hence the
        # cumbersome code below
    }
    _trace("SSLeay methods: " . join(" ", @list));
    foreach my $ssl (@{$cfg{'versions'}}) {
        next if ($cfg{$ssl} == 0);  # don't check what's disabled by option
        if (_is_do('cipherraw')) {  # +cipherraw does not depend on other libraries
            if ($ssl eq 'DTLSv1') {
                _warn("140: SSL version '$ssl': not supported by '$me +cipherraw'; not checked");
                next;
            }
            push(@{$cfg{'version'}}, $ssl);
            next;
        }
        # following checks for these commands only
        $cfg{$ssl} = 0; # reset to simplify further checks
        if ($ssl !~ /$cfg{'regex'}->{'SSLprot'}/) {
            _warn("141: SSL version '$ssl': not supported; not checked");
            next;
        }
        # Net::SSLeay  only supports methods for those SSL protocols which were
        # available at the time of compiling  Net::SSLeay. The support of these
        # protocols is not checked dynamically when building Net::SSLeay.
        # Net::SSLeay's config script simply relies on the definitions found in
        # the specified include files of the underlaying  SSL library (which is
        # is openssl usually).
        # Unfortunately,  there are situations where the assumptions at compile
        # time do not match the conditions at runtime. Then  Net::SSLeay  bails
        # out with error like:
        #   Can't locate auto/Net/SSLeay/CTX_v2_new.al in @INC ...
        # which means that  Net::SSLeay  was build without support for SSLv2.
        # To avoid bothering users with such messages (see above), or even more
        # errors or program aborts, we check for the availability of all needed
        # methods.  Sometimes, for whatever reason,  the user may know that the
        # warning can be avoided.  Therfore the  --ssl-lazy option can be used,
        # which simply disables the check.
        if ($cfg{'ssl_lazy'}>0) {
            push(@{$cfg{'version'}}, $ssl);
            $cfg{$ssl} = 1;
            next;
        }
        # Check for high-level API functions, like SSLv2_method, also possible
        # would be    Net::SSLeay::CTX_v2_new,  Net::SSLeay::CTX_tlsv1_2_new
        # and similar calls.
        # Net::SSLeay::SSLv23_method is missing in some  Net::SSLeay versions,
        # as we don't use it, there is no need to check for it.
        # TODO: DTLSv9 which is DTLS 0.9 ; but is this really in use?
        $typ = 0;
        $typ++ if (($ssl eq 'SSLv2')   and (grep{/^SSLv2_method$/}    @list));
        $typ++ if (($ssl eq 'SSLv3')   and (grep{/^SSLv3_method$/}    @list));
        $typ++ if (($ssl eq 'TLSv1')   and (grep{/^TLSv1_method$/}    @list));
        $typ++ if (($ssl eq 'TLSv11')  and (grep{/^TLSv1_1_method$/}  @list));
        $typ++ if (($ssl eq 'TLSv12')  and (grep{/^TLSv1_2_method$/}  @list));
        $typ++ if (($ssl eq 'TLSv13')  and (grep{/^TLSv1_3_method$/}  @list));
        $typ++ if (($ssl eq 'DTLSv1')  and (grep{/^DTLSv1_method$/}   @list));
        $typ++ if (($ssl eq 'DTLSv11') and (grep{/^DTLSv1_1_method$/} @list));
        $typ++ if (($ssl eq 'DTLSv12') and (grep{/^DTLSv1_2_method$/} @list));
        $typ++ if (($ssl eq 'DTLSv13') and (grep{/^DTLSv1_3_method$/} @list));
        $typ++ if (($ssl eq 'SSLv2')   and (grep{/^SSLv23_method$/}   @list));
        $typ++ if (($ssl eq 'SSLv3')   and (grep{/^SSLv23_method$/}   @list));
        # TODO: not sure if SSLv23_method  also supports TLSv1, TLSv11, TLSv12
        if ($typ > 0) {
            push(@{$cfg{'version'}}, $ssl);
            $cfg{$ssl} = 1;
        } else {
            _warn("143: SSL version '$ssl': not supported by Net::SSLeay; not checked");
            _hint("consider using '+cipherall' instead") if (_is_do('cipher'));
        }
    } # $ssl

    if (! _is_do('version')) {
        _v_print("supported SSL versions: @{$cfg{'versions'}}");
        _v_print("  checked SSL versions: @{$cfg{'version'}}");
    }
    return;
} # _check_SSL_methods

sub _enable_sclient     {
    # enable internal functionality based on available functionality of openssl s_client
    # SEE Note:OpenSSL s_client
    my $opt = shift;
    _y_CMD("  check openssl s_client cpapbility $opt ...") if ($cfg{verbose} > 0);
    my $txt = $cfg{'openssl'}->{$opt}[1];
    my $val = $cfg{'openssl'}->{$opt}[0];   # 1 if supported
    if ($val == 0) {
        if ($opt =~ m/^-(?:alpn|npn|curves)$/) {
            # no warning for external openssl, as -alpn or -npn is only used with +cipher
            if ($cmd{'extciphers'} > 0) {
            _warn("144: openssl s_client does not support '$opt'; $txt") if ($txt ne "");
            }
        } else {
            _warn("145: openssl s_client does not support '$opt'; $txt") if ($txt ne "");
        }
        if ($opt eq '-tlsextdebug') {   # additional warning
            _warn("146: openssl -tlsextdebug not supported; following results may be wrong: +heartbeat, +heartbleed, +session_ticket, +session_lifetime");
        }
        # switch $opt {
        $cfg{'use_reconnect'} = $val  if ($opt eq '-reconnect');
        $cfg{'use_extdebug'}  = $val  if ($opt eq '-tlsextdebug');
        $cfg{'usealpn'}       = $val  if ($opt eq '-alpn');
        $cfg{'usenpn'}        = $val  if ($opt eq '-npn');
        $cfg{'sni'}           = $val  if ($opt eq '-servername');
        $cfg{'ca_file'}       = undef if ($opt =~ /^-CAfile/i);
        $cfg{'ca_path'}       = undef if ($opt =~ /^-CApath/i);
        # }
    }
    # TODO: remove commands, i.e. +s_client, +heartbleed, from $cmd{do}
    #    -fallback_scsv: remove +scsv and +fallback
    return;
} # _enable_sclient

sub _reset_openssl      {
    # reset all %cfg and %cmd settings according openssl executable
    $cmd{'openssl'}     = "";
    $cmd{'extopenssl'}  = 0;
    $cmd{'extsclient'}  = 0;
    $cmd{'extciphers'}  = 0;
    # TODO: Net::SSLinfo not yet included ...
    #foreach my $opt (Net::SSLinfo::s_client_get_optionlist()) {
    #    $cfg{'openssl'}->{$opt}[0] = 0;
    #}
    return;
} # _reset_openssl

sub _check_openssl      {
    _y_CMD("  check cpapbilities of openssl ...");
    return if ($cmd{'openssl'} eq "");          # already checked and warning printed
    $Net::SSLinfo::openssl = $cmd{'openssl'};   # this version should be checked
    $Net::SSLinfo::trace   = $cfg{'trace'};
        # save to set $Net::SSLinfo::* here,
        # will be redifined later, see: set defaults for Net::SSLinfo
    if (not defined Net::SSLinfo::s_client_check()) {
        _warn("147: '$cmd{'openssl'}' not available; all openssl functionality disabled");
        _hint("consider using '--openssl=/path/to/openssl'");
        _reset_openssl();
    }
    # NOTE: if loading Net::SSLinfo failed, then we get a Perl warning here:
    #        Undefined subroutine &Net::SSLinfo::s_client_check called at ...
    # Net::SSLinfo::s_client_check() is used to check openssl's capabilities.
    # For an example output SEE Note:OpenSSL s_client
    # Each capabilitiy can be queried with  Net::SSLinfo::s_client_opt_get().
    # I.g. all checks are done in  Net::SSLinfo::s_client_*(),  but no proper
    # error messages are printed there.  Hence the checks are done here again
    # to disable all unavailable functionality with a warning.  Finally store
    # result (capabilitiy is supported or not) in $cfg{'openssl'} .
    foreach my $opt (Net::SSLinfo::s_client_get_optionlist()) {
        # Perl warning  "Use of uninitialized value in ..."  here indicates
        # that cfg{openssl} is not properly initialized
        my $val = Net::SSLinfo::s_client_opt_get($opt);
           $val = 0 if ($val eq '<<openssl>>'); # TODO: <<openssl>> from Net::SSLinfo
        # _dbx "$opt $val";
        $cfg{'openssl'}->{$opt}[0] = $val;
        next if ($cfg{'openssl'}->{$opt}[1] eq "<<NOT YET USED>>");
        _enable_sclient($opt);
    }
    # TODO: checks not yet complete
    # TODO: should check openssl with a real connection
    return;
} # _check_openssl

sub _init_opensslexe    {
    # check if openssl exists, return full path
    # i.g. we may rely on bare word  openssl  which then would be found using
    # $PATH, but it's better to have a clear definition right away because it
    # avoids errors
    # $cmd{'openssl'} not passed as parameter, as it will be changed here
    my $exe     = "";
    foreach my $p ("", split(/:/, $ENV{'PATH'})) { # try to find path
        # ""  above ensures that full path in $openssl will be checked
        $exe = "$p/$cmd{'openssl'}";
        last if (-e $exe);
        $exe = "";
    }
    $exe =~ s#//#/#g;       # make a nice path (see first path "" above)
    if ($exe eq "" or $exe eq "/") {
        _warn("149: no executable for '$cmd{'openssl'}' found; all openssl functionality disabled");
        _hint("consider using '--openssl=/path/to/openssl'");
        _reset_openssl();
    } else {
        $cmd{'openssl'} = $exe;
    }
    _v_print("_init_opensslexe: $exe");
    return;
} # _init_opensslexe

sub _init_openssldir    {
    # returns openssl-specific path for CAs; checks if OPENSSLDIR/certs exists
    # resets cmd{'openssl'}, cmd{'extopenssl'} and cmd{'extsclient'} on error
    # SEE Note:OpenSSL CApath
    # $cmd{'openssl'} not passed as parameter, as it will be changed here
    my $dir = qx($cmd{'openssl'} version -d);   # get something like: OPENSSLDIR: "/usr/local/openssl"
    chomp $dir;
        # if qx() above failed, we get: Use of uninitialized value $dir in ...
    my $status  = $?;
    my $error   = $!;
    my $capath  = "";
    local   $\  = "\n";
    _trace("_init_openssldir: $dir");
    if (($error ne "") && ($status != 0)) { # we ignore error messages for status==0
        # When there is a status and an error message, external call failed.
        # Print error message and disable external openssl.
        # In rare cases (i.e. VM with low memory) external call fails due to
        # malloc() problems, in this case print an additional warning.
        # Note that low memory affects external calls only *but not* further
        # control flow herein as Perl already managed to load the script.
        # For defence programming  print()  is used insted of  _warn().
        print STR_WARN, "002: perl returned error: '$error'\n";
        if ($error =~ m/allocate memory/) {
            print STR_WARN, "003: using external programs disabled.\n";
            print STR_WARN, "004: data provided by external openssl may be shown as:  <<openssl>>\n";
        }
        _reset_openssl();
        $status = 0;  # avoid following warning below
    } else {
        # process only if no errors to avoid "Use of uninitialized value"
        my $openssldir = $dir;
        $dir =~ s#[^"]*"([^"]*)"#$1#;
        if (-e "$dir/certs") {
            $capath = "$dir/certs";
        } else {    # no directory found, add path to common paths as last resort
            _warn("148: 'openssl version -d' returned not existing: '$openssldir'; ca_path not set .");
            unshift(@{$cfg{'ca_paths'}}, $dir); # dirty hack (but dosn't harm:)
        }
    }
    if ($status != 0) {                     # on Windoze status may be 256
        $cmd{'openssl'}    = "";
        print STR_WARN, "005: perl returned status: '$status' ('" . ($status>>8) . "')\n";
            # no other warning here, see "some checks are missing" later,
            # this is to avoid bothering the user with warnings, when not used
        # $capath = ""; # should still be empty
    }
    _trace("_init_openssldir: ca_path=$cfg{'ca_paths'} .");
    return $capath;
} # _init_openssldir

sub _initchecks_score   {
    # set all default score values here
    $checks{$_}->{score} = 10 foreach (keys %checks);
    # some special values %checks{'sts_maxage*'}
    $checks{'sts_maxage0d'}->{score} =   0; # very weak
    $checks{'sts_maxage1d'}->{score} =  10; # weak
    $checks{'sts_maxage1m'}->{score} =  20; # low
    $checks{'sts_maxage1y'}->{score} =  70; # medium
    $checks{'sts_maxagexy'}->{score} = 100; # high
    $checks{'sts_maxage18'}->{score} = 100; # high
    foreach (keys %checks) {
        $checks{$_}->{score} = 90 if (m/WEAK/i);
        $checks{$_}->{score} = 30 if (m/LOW/i);
        $checks{$_}->{score} = 10 if (m/MEDIUM/i);
    }
    return;
} # _initchecks_score

sub _initchecks_val     {
    # set all default check values here
    $checks{$_}->{val}   = "" foreach (keys %checks);
    # some special values %checks{'sts_maxage*'}
    $checks{'sts_maxage0d'}->{val}  =        1;
    $checks{'sts_maxage1d'}->{val}  =    86400; # day
    $checks{'sts_maxage1m'}->{val}  =  2592000; # month
    $checks{'sts_maxage1y'}->{val}  = 31536000; # year
    $checks{'sts_maxagexy'}->{val}  = 99999999;
    $checks{'sts_maxage18'}->{val}  = 10886400; # 18 weeks
    foreach (keys %checks) {
        $checks{$_}->{val}   =  0 if (m/$cfg{'regex'}->{'cmd-sizes'}/);
        $checks{$_}->{val}   =  0 if (m/$cfg{'regex'}->{'SSLprot'}/);
    }
    return;
} # _initchecks_val

sub _init_all           {
    # set all default values here
    $cfg{'done'}->{'init_all'}++;
    _trace("_init_all(){}");
    _initchecks_score();
    _initchecks_val();
    $cfg{'hints'}->{$_} = $text{'hints'}->{$_} foreach (keys %{$text{'hints'}});
    # _init_openssldir();
        # not done here because it needs openssl command, which may be set by
        # options, hence the call must be done after reading arguments
    return;
} # _init_all
_init_all();   # initialize defaults in %checks (score, val)

sub _resetchecks        {
    # reset values
    foreach (keys %{$cfg{'done'}}) {
        next if (!m/^check/);  # only reset check*
        $cfg{'done'}->{$_} = 0;
    }
    $cfg{'done'}->{'ciphers_all'} = 0;
    $cfg{'done'}->{'ciphers_get'} = 0;
    _initchecks_val();
    return;
}

sub _prot_cipher($$)    { my @txt = @_; return " " . join(":", @txt); }
    # return string consisting of given parameters separated by : and prefixed with a space
    # (mainly used to concatenate SSL Version and cipher suite name)

sub _getscore($$$)      {
    # return score value from given hash; 0 if given value is empty, otherwise score to given key
    my $key     = shift;
    my $value   = shift || "";
    my $hashref = shift;# list of checks
    my %hash    = %$hashref;
    return 0 if ($value eq "");
    my $score   = $hash{$key}->{score} || 0;
    _trace("_getscore($key, '$value')\t= $score");
    return $score;
} # _getscore

sub _cfg_set($$);       # avoid: main::_cfg_set() called too early to check prototype at ...
sub _cfg_set_from_file($$) {
    # read values to be set in configuration from file
    my $typ = shift;    # type of config value to be set
    my $fil = shift;    # filename
    _trace("_cfg_set: read $fil \n");
    my $line ="";
    my $fh;
    # NOTE: critic complains with InputOutput::RequireCheckedOpen, which
    #       is a false positive, because  Perl::Critic  seems not to understand
    #       the logic of "open() && do{}; warn();",  hence the code was changed
    #       to use an  if-condition
    if (open($fh, '<:encoding(UTF-8)', $fil)) {
        push(@{$dbx{file}}, $fil);
        _print_read("$fil", "USER-FILE configuration file") if ($cfg{'out_header'} > 0);
        while ($line = <$fh>) {
            #
            # format of each line in file must be:
            #    Lines starting with  =  are comments and ignored.
            #    Anthing following (and including) a hash is a comment
            #    and ignored. Empty lines are ignored.
            #    Settings must be in format:  key=value
            #       where white spaces are allowed around =
            chomp $line;
            $line =~ s/\s*#.*$// if ($typ !~ m/^CFG-text/i);
                # remove trailing comments, but CFG-text may contain hash (#)
            next if ($line =~ m/^\s*=/);# ignore our header lines (since 13.12.11)
            next if ($line =~ m/^\s*$/);# ignore empty lines
            _trace("_cfg_set: set $line ");
            _cfg_set($typ, $line);
        }
        close($fh);
    };
    _warn("070: configuration file '$fil' cannot be opened: $! ; file ignored");
    return;
} #  _cfg_set_from_file

sub _cfg_set($$)        {
    # set value in configuration %cfg, %checks, %data, %text
    # $typ must be any of: CFG-text, CFG-score, CFG-cmd-*
    # if given value is a file, read settings from that file
    # otherwise given value must be KEY=VALUE format;
    # NOTE: may define new commands for CFG-cmd
    my $typ = shift;    # type of config value to be set
    my $arg = shift;    # KEY=VAL or filename
    my ($key, $val);
    _trace("_cfg_set($typ, ){");
    if ($typ !~ m/^CFG-$cfg{'regex'}->{'cmd-cfg'}/) {
        _warn("071: configuration key unknown '$typ'; setting ignored");
        goto _CFG_RETURN;
    }
    if (($arg =~ m|^[a-zA-Z0-9,._+#()\/-]+|) and (-f "$arg")) { # read from file
        # we're picky about valid filenames: only characters, digits and some
        # special chars (this should work on all platforms)
        if ($cgi == 0) {
            _warn("072: configuration files are not read in CGI mode; ignored");
            return;
        }
        _cfg_set_from_file($typ, $arg);
        goto _CFG_RETURN;
    } # read file

    ($key, $val) = split(/=/, $arg, 2); # left of first = is key
    $key =~ s/[^a-zA-Z0-9_?=+-]*//g;    # strict sanatize key
    $val =  "" if not defined $val;     # avoid warnings when not KEY=VALUE
    $val =~ s/^[+]//;                   # remove first + in command liss
    $val =~ s/ [+]/ /g;                 # remove + in commands

    if ($typ eq 'CFG-cmd') {            # set new list of commands $arg
        $typ = 'cmd-' . $key ;# the command to be set, i.e. cmd-http, cmd-sni, ...
        _trace("_cfg_set: cfg{$typ}, KEY=$key, CMD=$val");
        @{$cfg{$typ}} = ();
        push(@{$cfg{$typ}}, split(/\s+/, $val));
        foreach my $key (@{$cfg{$typ}}){# check for mis-spelled commands
            next if (_is_hashkey($key, \%checks) > 0);
            next if (_is_hashkey($key, \%data) > 0);
            next if (_is_intern( $key) > 0);
            next if (_is_member( $key, \@{$cfg{'cmd-NL'}}) > 0);
            if ($key eq 'protocols') {  # valid before 17.02.26; behave smart for old rc-files
                push(@{$cfg{$typ}}, 'next_protocols');
                next;
            }
            if ($key eq 'default') {    # valid before 14.11.14; behave smart for old rc-files
                push(@{$cfg{$typ}}, 'cipher_selected');
                _warn("073: configuration: please use '+cipher-selected' instead of '+$key'; setting ignored");
                next;
            }
            _warn("074: configuration: unknown command '+$key' for '$typ'; setting ignored");
        }
        # check if it is a known command, otherwise add it and print warning
        if ((_is_member($key, \@{$cfg{'commands'}})
           + _is_member($key, \@{$cfg{'commands-CMD'}})
           + _is_member($key, \@{$cfg{'commands-INT'}})
            ) < 1) {
            # NOTE: new commands are added only if they are not yet defined,
            # wether as internal, as summary or as (previously defined) user
            # command. The new command must also consists only of  a-z0-9_.-
            # charchters.  If any of these conditions fail, the command will
            # be ignored silently.
            if (_is_member("cmd-$key", \@{$cfg{'commands-CMD'}}) == 0) {
                # needed more checks, as these commands are defined as cmd-*
                if ($key =~ m/^([a-z0-9_.-]+)$/) {
                    # whitelust check for valid characters; avoid injections
                    push(@{$cfg{'commands-USR'}}, $key);
                    _warn("043: command '+$key' specified by user") if ((grep{/--v/i} @ARGV) > 0);
                }
            }
        }
    }

    # invalid keys are silently ignored (Perl is that clever:)

    if ($typ eq 'CFG-score') {          # set new score value
        _trace("_cfg_set: KEY=$key, SCORE=$val");
        if ($val !~ m/^(?:\d\d?|100)$/) { # allow 0 .. 100
            _warn("076: configuration: invalid score value '$val'; setting ignored");
            goto _CFG_RETURN;
        }
        $checks{$key}->{score} = $val if ($checks{$key});
    }

    $val =~ s/(\\n)/\n/g;
    $val =~ s/(\\r)/\r/g;
    $val =~ s/(\\t)/\t/g;
    _trace("_cfg_set: KEY=$key, LABEL=$val");
    $checks{$key}->{txt} = $val if ($typ =~ /^CFG-check/);
    $data{$key}  ->{txt} = $val if ($typ =~ /^CFG-data/);
    $data{$key}  ->{txt} = $val if ($typ =~ /^CFG-info/);   # alias for --cfg-data
    $cfg{'hints'}->{$key}= $val if ($typ =~ /^CFG-hint/);   # allows CFG-hints also
    $text{$key}          = $val if ($typ =~ /^CFG-text/);   # allows CFG-texts also
    $scores{$key}->{txt} = $val if ($typ =~ /^CFG-scores/); # BUT: CFG-score is different
    $scores{$key}->{txt} = $val if ($key =~ m/^check_/);    # contribution to lazy usage

    _CFG_RETURN:
    _trace("_cfg_set() }");
    return;
} # _cfg_set

sub _cfg_set_cipher($$) {
    # set value for security of cipher in configuration %ciphers
    my ($typ, $arg) = @_;
    my ($key, $val) = split(/=/, $arg, 2); # left of first = is key
    #dbx# _dbx "arg: $arg # key: $key # val: $val";
    ${$ciphers{$key}}[0] = $val;
    #dbx# _dbx @{$ciphers{$key}};
    return;
} # _cfg_set_cipher

# check functions for array members and hash keys
sub __SSLinfo($$$)      {
    # wrapper for Net::SSLinfo::*() functions
    # Net::SSLinfo::*() return raw data, depending on $cfg{'format'}
    # these values will be converted to o-saft's preferred format
    my ($cmd, $host, $port) = @_;
    my $val = "<<__SSLinfo: unknown command: '$cmd'>>";
    my $ext = "";
    $val =  Net::SSLinfo::fingerprint(      $host, $port) if ($cmd eq 'fingerprint');
    $val =  Net::SSLinfo::fingerprint_hash( $host, $port) if ($cmd eq 'fingerprint_hash');
    $val =  Net::SSLinfo::fingerprint_sha2( $host, $port) if ($cmd eq 'fingerprint_sha2');
    $val =  Net::SSLinfo::fingerprint_sha1( $host, $port) if ($cmd eq 'fingerprint_sha1');
    $val =  Net::SSLinfo::fingerprint_md5(  $host, $port) if ($cmd eq 'fingerprint_md5');
    $val =  Net::SSLinfo::pubkey_value(     $host, $port) if ($cmd eq 'pubkey_value');
    $val =  Net::SSLinfo::sigkey_value(     $host, $port) if ($cmd eq 'sigkey_value');
    $val =  Net::SSLinfo::heartbeat(        $host, $port) if ($cmd eq 'heartbeat');
    $val =  Net::SSLinfo::extensions(       $host, $port) if ($cmd =~ /^ext(?:ensions|_)/);
    $val =  Net::SSLinfo::tlsextdebug(      $host, $port) if ($cmd eq 'tlsextdebug');
    if ($cmd eq 'tlsextensions') {
        $val =  Net::SSLinfo::tlsextensions($host, $port);
        $val =~ s/^\s*//g;
        $val =~ s/([\n\r])/; /g;
    }
    # ::ocspid may return multiple lines, something like:
    #   Subject OCSP hash: 57F4D68F870A1698065F803BE9D967B1B2B9E491
    #   Public key OCSP hash: BF788D39424E219C62538F72701E1C87C4F667EA
    # it's also assumed that both lines are present
    if ($cmd =~ /ocspid/) {
        $val =  Net::SSLinfo::ocspid($host, $port);
        $val =~ s/^\n?\s+//g;   # remove leading spaces
        $val =~ s/([\n\r])/; /g;# remove newlines
    }
    if ($cmd =~ /ocsp_subject_hash/) {
        $val =  Net::SSLinfo::ocspid($host, $port);
        $val =~ s/^[^:]+:\s*//;
        $val =~ s/.ublic[^:]+:\s*.*//;
    }
    if ($cmd =~ /ocsp_public_hash/) {
        $val =  Net::SSLinfo::ocspid($host, $port);
        $val =~ s/^[^:]+:\s*//;
        $val =~ s/^[^:]+:\s*//; # TODO: quick&dirty
    }
    if ($cmd =~ m/ext_/) {
        # all following are part of Net::SSLinfo::extensions(), now extract parts
        # The extension section in the certificate starts with
        #    X509v3 extensions:
        # then each extension starts with a string prefixed by  X509v3
        # except following:
        #    Authority Information Access
        #    Netscape Cert Type
        #    CT Precertificate SCTs
        #
        # Example www.microsoft.com (03/2016)
        #    X509v3 extensions:
        #        X509v3 Subject Alternative Name:
        #            DNS:privacy.microsoft.com, DNS:www.microsoft.com, DNS:wwwqa.microsoft.com
        #        X509v3 Basic Constraints:
        #            CA:FALSE
        #        X509v3 Key Usage: critical
        #            Digital Signature, Key Encipherment
        #        X509v3 Extended Key Usage:
        #            TLS Web Server Authentication, TLS Web Client Authentication
        #        X509v3 Certificate Policies:
        #            Policy: 2.16.840.1.113733.1.7.23.6
        #              CPS: https://d.symcb.com/cps
        #              User Notice:
        #                Explicit Text: https://d.symcb.com/rpa
        #        X509v3 Authority Key Identifier:
        #            keyid:0159ABE7DD3A0B59A66463D6CF200757D591E76A
        #        X509v3 CRL Distribution Points:
        #            Full Name:
        #              URI:http://sr.symcb.com/sr.crl
        #        Authority Information Access:
        #            OCSP - URI:http://sr.symcd.com
        #            CA Issuers - URI:http://sr.symcb.com/sr.crt
        #        CT Precertificate SCTs:
        #            Signed Certificate Timestamp:
        #                Version   : v1(0)
        #                Log ID    : DDEB1D2B7A0D4FA6208B81AD8168707E:
        #                            2E8E9D01D55C888D3D11C4CDB6ECBECC
        #                Timestamp : Mar 24 212018.939 2016 GMT
        #                Extensions: none
        #                Signature : ecdsa-with-SHA256
        #                            304602210095B30A493A8E8B253004AD:
        #                            A971E0106BE0CC97B6FF2908FDDBBB3D:
        #                            B8CEBFFCF8022100F37AA34DE5BE38D8:
        #                            5A03EE8B3AAE451C0014A802C079AA34:
        #                            9C20BAF44C54CF36
        #            Signed Certificate Timestamp:
        #                Version   : v1(0)
        #                Log ID    : A4B90990B418581487BB13A2CC67700A:
        #                            3C359804F91BDFB8E377CD0EC80DDC10
        #                Timestamp : Mar 24 212018.983 2016 GMT
        #                Extensions: none
        #                Signature : ecdsa-with-SHA256
        #                            3046022100C877DC1DBBDA2FBC7E5E63:
        #                            60A7EAB31EED42066F91C724963EE0CE:
        #                            80C8EBCE8C022100D5865704F32487CF:
        #                            FF021F1C8A955303E496630CAE3C0F18:
        #                            B8CDDFD4798365FD
        #        ...
        #
        # Example microsoft.com
        #    X509v3 extensions:
        #        X509v3 Key Usage:
        #            Digital Signature, Key Encipherment, Data Encipherment
        #        X509v3 Extended Key Usage:
        #            TLS Web Server Authentication, TLS Web Client Authentication
        #        S/MIME Capabilities:
        #            0000 - 30 69 30 0e 06 08 2a 86-48 86 f7 0d 03   0i0...*.H....
        #            000d - 02 02 02 00 80 30 0e 06-08 2a 86 48 86   .....0...*.H.
        #            001a - f7 0d 03 04 02 02 00 80-30 0b 06 09 60   ........0...`
        #            0027 - 86 48 01 65 03 04 01 2a-30 0b 06 09 60   .H.e...*0...`
        #            0034 - 86 48 01 65 03 04 01 2d-30 0b 06 09 60   .H.e...-0...`
        #            0041 - 86 48 01 65 03 04 01 02-30 0b 06 09 60   .H.e....0...`
        #            004e - 86 48 01 65 03 04 01 05-30 07 06 05 2b   .H.e....0...+
        #            005b - 0e 03 02 07 30 0a 06 08-2a 86 48 86 f7   ....0...*.H..
        #            0068 - 0d 03 07                                 ...
        #        X509v3 Subject Key Identifier:
        #            84C60E3B0FA69BF6EE0640CB02041B5F59340F73
        #        X509v3 Authority Key Identifier:
        #            keyid:51AF24269CF468225780262B3B4662157B1ECCA5
        #        X509v3 CRL Distribution Points:
        #            Full Name:
        #              URI:http://mscrl.microsoft.com/pki/mscorp/crl/msitwww2.crl
        #              URI:http://crl.microsoft.com/pki/mscorp/crl/msitwww2.crl
        #        Authority Information Access:
        #            CA Issuers - URI:http://www.microsoft.com/pki/mscorp/msitwww2.crt
        #            OCSP - URI:http://ocsp.msocsp.com
        #        X509v3 Certificate Policies:
        #            Policy: 1.3.6.1.4.1.311.42.1
        #              CPS: http://www.microsoft.com/pki/mscorp/cps
        #        1.3.6.1.4.1.311.21.10:
        #            0000 - 30 18 30 0a 06 08 2b 06-01 05 05 07 03   0.0...+......
        #            000d - 01 30 0a 06 08 2b 06 01-05 05 07 03 02   .0...+.......
        #        ...
        #
        # Example bsi.bund.de (03/2016)
        #    X509v3 extensions:
        #        X509v3 Authority Key Identifier:
        #            keyid:5404296FA293C6903145C03DDE2BE20A6980925F
        #        X509v3 Key Usage: critical
        #            Digital Signature, Key Encipherment
        #        X509v3 Extended Key Usage:
        #            TLS Web Client Authentication, TLS Web Server Authentication
        #        X509v3 Subject Key Identifier:
        #            1BA42D9746798AE2AE91D60AA60BE40FAA8A299E
        #        X509v3 Certificate Policies:
        #            Policy: 1.3.6.1.4.1.7879.13.2
        #              CPS: http://www.telesec.de/serverpass/cps.html
        #            Policy: 2.23.140.1.2.2
        #        X509v3 CRL Distribution Points:
        #            Full Name:
        #              URI:http://crl.serverpass.telesec.de/rl/TeleSec_ServerPass_DE-2.crl
        #            Full Name:
        #              URI:ldap://ldap.serverpass.telesec.de/cn=TeleSec%20ServerPass%20DE-2,ou=T-Systems%20Trust%20Center,o=T-Systems%20International%20GmbH,c=de?certificateRevocationlist?base?certificateRevocationlist=*
        #        Authority Information Access:
        #            OCSP - URI:http://ocsp.serverpass.telesec.de/ocspr
        #            CA Issuers - URI:http://crl.serverpass.telesec.de/crt/TeleSec_ServerPass_DE-2.cer
        #            CA Issuers - URI:ldap://ldap.serverpass.telesec.de/cn=TeleSec%20ServerPass%20DE-2,ou=T-Systems%20Trust%20Center,o=T-Systems%20International%20GmbH,c=de?cACertificate
        #        X509v3 Basic Constraints: critical
        #            CA:FALSE
        #        X509v3 Subject Alternative Name:
        #            DNS:www.bsi.bund.de
        #
        # Example www.bsi.de (06/2016)
        #    X509v3 CRL Distribution Points:
        #
        #         Full Name:
        #           URI:http://crl.serverpass.telesec.de/rl/TeleSec_ServerPass_DE-2.crl
        #
        #         Full Name:
        #           URI:ldap://ldap.serverpass.telesec.de/cn=TeleSec%20ServerPass%20DE-2,ou=T-Systems%20Trust%20Center,o=T-Systems%20International%20GmbH,c=de?certificateRevocationlist?base?certificateRevocationlist=*
        #     Authority Information Access:
        #         OCSP - URI:http://ocsp.serverpass.telesec.de/ocspr
        #         CA Issuers - URI:http://crl.serverpass.telesec.de/crt/TeleSec_ServerPass_DE-2.cer
        #         CA Issuers - URI:ldap://ldap.serverpass.telesec.de/cn=TeleSec%20ServerPass%20DE-2,ou=T-Systems%20Trust%20Center,o=T-Systems%20International%20GmbH,c=de?cACertificate
        #
        # handled in RegEx below which matches next extension, if any.
        $val .= " X509";# add string to match last extension also
        my $rex = '\s*(.*?)(?:X509|Authority|Netscape|CT Precertificate).*';
            # FIXME: the RegEx should match OIDs also
            # FIXME: otherwise OID extensions are added as value to the
            #        preceding extension, see example above (4/2016)
        # FIXME: replace following list of RegEx with a loop over the extensions
        $ext = $val;
        $val =~ s#.*?Authority Information Access:$rex#$1#ms    if ($cmd eq 'ext_authority');
        $val =~ s#.*?Authority Key Identifier:$rex#$1#ms        if ($cmd eq 'ext_authorityid');
        $val =~ s#.*?Basic Constraints:$rex#$1#ms               if ($cmd eq 'ext_constraints');
        $val =~ s#.*?Key Usage:$rex#$1#ms                       if ($cmd eq 'ext_keyusage');
        $val =~ s#.*?Subject Key Identifier:$rex#$1#ms          if ($cmd eq 'ext_subjectkeyid');
        $val =~ s#.*?Certificate Policies:$rex#$1#ms            if ($cmd =~ /ext_cps/);
        $val =~ s#.*?CPS\s*:\s*([^\s\n]*).*#$1#ms               if ($cmd eq 'ext_cps_cps');
        $val =~ s#.*?Policy\s*:\s*(.*?)(?:\n|CPS|User).*#$1#ims if ($cmd eq 'ext_cps_policy');
        $val =~ s#.*?User\s*Notice:\s*(.*?)(?:\n|CPS|Policy).*#$1#ims  if ($cmd eq 'ext_cps_notice');
        $val =~ s#.*?CRL Distribution Points:$rex#$1#ms         if ($cmd eq 'ext_crl');
        $val =~ s#.*?Extended Key Usage:$rex#$1#ms              if ($cmd eq 'ext_extkeyusage');
        $val =~ s#.*?Netscape Cert Type:$rex#$1#ms              if ($cmd eq 'ext_certtype');
        $val =~ s#.*?Issuer Alternative Name:$rex#$1#ms         if ($cmd eq 'ext_issuer');
        if ($cmd eq 'ext_crl') {
            $val =~ s#\s*Full Name:\s*##imsg;       # multiple occourances possible
            $val =~ s#(\s*URI\s*:)# #msg;
        }
        $val =  "" if ($ext eq $val);    # nothing changed, then expected pattern is missing
    }
# TODO: move code for formatting to print*()
    if ($cmd =~ /ext(?:ensions|debug|_)/) {
        # grrr, formatting extensions is special, take care for traps ...
        if ($cfg{'format'} ne "raw") {
            $val =~ s/([0-9a-f]):([0-9a-f])/$1$2/ig; # remove : inside hex (quick&dirty)
            # it was quick&dirty, correct some failures
            $val =~ s/(keyid)/$1:/i;
            $val =~ s/(CA)(FALSE)/$1:$2/i;
            if ($cmd eq 'extensions') {
                # extensions are special as they contain multiple values
                # values are separated by emty lines
                $val =~ s/\n\n+/\n/g;   # remove empty lines
            } else {
                $val =~ s/\s\s+/ /g;    # remove multiple spaces
            }
        }
        return $val; # ready!
    }
# TODO: move code for formatting to print*()
    if ($cfg{'format'} ne "raw") {
        $val =  "" if not defined $val; # avoid warnings
        $val =~ s/^\s+//g;      # remove leading spaces
        $val =~ s/\n\s+//g;     # remove trailing spaces
        $val =~ s/\n/ /g;
        $val =~ s/\s\s+/ /g;    # remove multiple spaces
        $val =~ s/([0-9a-f]):([0-9a-f])/$1$2/ig; # remove : inside hex (quick&dirty)
    }
    return $val;
} # __SSLinfo

sub _subst($$)          { my ($is,$txt)=@_; $is=~s/@@/$txt/; return $is; }
    # return given text with '@@' replaced by given value
sub _get_text($$)       { my ($is,$txt)=@_; return _subst($text{$is}, $txt); }
    # for given index of %text return text with '@@' replaced by given value
sub _need_this($)       {
    # returns >0 if any of the given commands is listed in $cfg{'$_'}
    my $key = shift;
    my $is  = join("|", @{$cfg{'do'}});
       $is  =~ s/\+/\\+/g;    # we have commands with +, needs to be escaped
    return grep{/^($is)$/} @{$cfg{$key}};
}
sub _need_cipher()      { return _need_this('need-cipher');     };
sub _need_default()     { return _need_this('need-default');    };
sub _need_checkssl()    { return _need_this('need-checkssl');   };
sub _need_checkalpn()   { return _need_this('need-checkalpn');  };
sub _need_checkbleed()  { return _need_this('need-checkbleed'); };
sub _need_checkchr()    { return _need_this('need-checkchr');   };
sub _need_checkdest()   { return _need_this('need-checkdest');  };
sub _need_check_dh()    { return _need_this('need-check_dh');   };
sub _need_checkhttp()   { return _need_this('need-checkhttp');  };
sub _need_checkprot()   { return _need_this('need-checkprot');  };
    # returns >0 if any  of the given commands is listed in $cfg{need-*}
sub _is_hashkey($$)     { my ($is,$ref)=@_; return grep({lc($is) eq lc($_)} keys %{$ref}); }
sub _is_member($$)      { my ($is,$ref)=@_; return grep({lc($is) eq lc($_)}      @{$ref}); }
sub _is_do($)           { my  $is=shift;    return _is_member($is, \@{$cfg{'do'}}); }
sub _is_intern($)       { my  $is=shift;    return _is_member($is, \@{$cfg{'commands-INT'}}); }
sub _is_hexdata($)      { my  $is=shift;    return _is_member($is, \@{$cfg{'data_hex'}});  }
sub _is_call($)         { my  $is=shift;    return _is_member($is, \@{$cmd{'call'}}); }
    # returns >0 if any of the given string is listed in $cfg{*}


#| definitions: check functions
#| -------------------------------------
sub _setvalue($){ my $val=shift; return ($val eq "") ? 'yes' : 'no (' . $val . ')'; }
    # return 'yes' if given value is empty, return 'no' otherwise
sub _isbeast($$){
    # return given cipher if vulnerable to BEAST attack, empty string otherwise
    my ($ssl, $cipher) = @_;
    return ""      if ($ssl    !~ /(?:SSL|TLSv1$)/); # TLSv11 or later are not vulnerable to BEAST
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'BEAST'}/);
    return "";
} # _isbeast
### _isbreach($)        { return "NOT YET IMPLEMEMNTED"; }
sub _isbreach($){
    # return 'yes' if vulnerable to BREACH
    return "";
# TODO: checks
    # To be vulnerable, a web application must:
    #      Be served from a server that uses HTTP-level compression
    #      Reflect user-input in HTTP response bodies
    #      Reflect a secret (such as a CSRF token) in HTTP response bodies
    #      *  agnostic to the version of TLS/SSL
    #      *  does not require TLS-layer compression
    #      *  works against any cipher suite
    #      *  can be executed in under a minute
} # _isbreach
sub _iscrime    {
    # return compression or SPDY/3 if available, empty string otherwise
    # $val is usually $data{'compression'}->{val}
    my ($val, $protocols) = @_;
    my $ret  = ($val =~ /$cfg{'regex'}->{'nocompression'}/) ? ""  : $val . " ";
       $ret .= ($protocols =~ /$cfg{'regex'}->{'isSPDY3'}/) ? "SPDY/3 " : "";
    #  http://zoompf.com/2012/09/explaining-the-crime-weakness-in-spdy-and-ssl
    return $ret;
} # _iscrime
sub _islucky($) { my $val=shift; return ($val =~ /$cfg{'regex'}->{'Lucky13'}/) ? $val : ""; }
    # return given cipher if vulnerable to Lucky 13 attack, empty string otherwise
sub _istime($)  { return 0; } # TODO: checks; good: AES-GCM or AES-CCM
sub _isfreak($$){
    # return given cipher if vulnerable to FREAK attack, empty string otherwise
    my ($ssl, $cipher) = @_;
    return ""      if ($ssl    !~ /(?:SSLv3)/); # TODO: probaly only SSLv3 is vulnerable
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'FREAK'}/);
    return "";
} # _isfreak
sub _islogjam($$) {
    # return given cipher if vulnerable to logjam attack, empty string otherwise
    my ($ssl, $cipher) = @_;
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'Logjam'}/);
    return "";
} # _islogjam
sub _isrobot($$){
    # return given cipher if vulnerable to ROBOT attack, empty string otherwise
    my ($ssl, $cipher) = @_;
   #return ""      if ($cipher =~ /$cfg{'regex'}->{'notROBOT'}/);
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'ROBOT'}/);
    return "";
} # _isrobot
sub _issloth($$){
    # return given cipher if vulnerable to SLOTH attack, empty string otherwise
    my ($ssl, $cipher) = @_;
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'SLOTH'}/);
    return "";
} # _issloth
sub _issweet($$){
    # return given cipher if vulnerable to Sweet32 attack, empty string otherwise
    my ($ssl, $cipher) = @_;
    return ""      if ($cipher =~ /$cfg{'regex'}->{'notSweet32'}/);
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'Sweet32'}/);
    return "";
} # _issweet
sub _ispfs($$)  { my ($ssl,$c)=@_; return ("$ssl-$c" =~ /$cfg{'regex'}->{'PFS'}/)  ?  ""  : $c; }
    # return given cipher if it does not support forward secret connections (PFS)
sub _isrc4($)   { my $val=shift; return ($val =~ /$cfg{'regex'}->{'RC4'}/)  ? $val . " "  : ""; }
    # return given cipher if it is RC4
sub _istr02102          {
    # return given cipher if it is not TR-02102 compliant, empty string otherwise
    # this is valid vor TR-02102 2013 and 2016
    my ($ssl, $cipher) = @_;
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'EXPORT'}/);
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'notTR-02102'}/);
    return $cipher if ($cipher !~ /$cfg{'regex'}->{'TR-02102'}/);
    return "";
} # _istr02102
sub _istr02102_strict   {
    # return given cipher if it is not TR-02102 compliant, empty string otherwise
    my ($ssl, $cipher) = @_;
    my $val = _istr02102($ssl, $cipher);
    if ($val eq "") {   # tsrict allows AES*-GCM only and no SHA-1
        return $cipher if ($cipher !~ /$cfg{'regex'}->{'AES-GCM'}/);
        return $cipher if ($cipher =~ /$cfg{'regex'}->{'notTR-02102'}/);
    }
    return $val;
} # _istr02102_strict
sub _istr02102_lazy     {
    # return given cipher if it is not TR-02102 compliant, empty string otherwise
    my ($ssl, $cipher) = @_;
    my $val = _istr02102($ssl, $cipher);
    return $val;
} # _istr02102_lazy
sub _istr03116_strict   {
    # return given cipher if it is not TR-03116 compliant, empty string otherwise
    my ($ssl, $cipher) = @_;
    return $cipher if ($ssl    ne "TLSv12");
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'EXPORT'}/);
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'notTR-03116'}/);
    return $cipher if ($cipher !~ /$cfg{'regex'}->{'TR-03116+'}/);
    return "";
} # _istr03116_strict
sub _istr03116_lazy     {
    # return given cipher if it is not TR-03116 compliant, empty string otherwise
    my ($ssl, $cipher) = @_;
    return $cipher if ($ssl    ne "TLSv12");
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'EXPORT'}/);
    return $cipher if ($cipher !~ /$cfg{'regex'}->{'TR-03116-'}/);
    return "";
} # _istr03116_lazy
sub _isrfc7525          {
    # return given cipher if it is not RFC 7525 compliant, empty string otherwise
    my ($ssl, $cipher) = @_;
    my $bit = get_cipher_bits($cipher);
    return $cipher if ($cipher !~ /$cfg{'regex'}->{'RFC7525'}/);
   # /notRFC7525/;
    return $cipher if ($cipher =~ /NULL/);
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'EXPORT'}/);
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'RC4orARC4'}/);
    return ""      if ($bit =~ m/^\s*$/);   # avoid Perl warnings if $bit empty
    return $cipher if ($bit < 128);
    return "";
} # _isrfc7525
sub _isfips($$)         {
    # return given cipher if it is not FIPS-140 compliant, empty string otherwise
    my ($ssl, $cipher) = @_;
    return $cipher if ($ssl    ne "TLSv1");
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'notFIPS-140'}/);
    return $cipher if ($cipher !~ /$cfg{'regex'}->{'FIPS-140'}/);
    return "";
} # _isfips
sub _isnsab($$)         {
    # return given cipher if it is not NSA Suite B compliant, empty string otherwise
# TODO:
} # _isnsab
sub _ispci($$)          {
    # return given cipher if it is not PCI compliant, empty string otherwise
# TODO: DH 1024+ is PCI compliant
    my ($ssl, $cipher) = @_;
    return $cipher if ($ssl    eq "SSLv2"); # SSLv2 is not PCI compliant
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'notPCI'}/);
    return "";
} # _ispci
sub _readframe($)       {
    # from https://github.com/noxxi/p5-scripts/blob/master/check-ssl-heartbleed.pl
    my $cl  = shift;
    my $len = 5;
    my $buf = '';
    vec( my $rin = '',fileno($cl),1 ) = 1;
    while ( length($buf)<$len ) {
        select( my $rout = $rin,undef,undef,$cfg{'timeout'} ) or return;
        sysread($cl,$buf,$len-length($buf),length($buf))  or return;
        $len = unpack("x3n",$buf) + 5 if length($buf) == 5;
    }
    (my $type, my $ver,$buf) = unpack("Cnn/a*",$buf);
    my @msg;
    if ( $type == 22 ) {
        while ( length($buf)>=4 ) {
            my $ht;
            ($ht,$len) = unpack("Ca3",substr($buf,0,4,''));
            $len = unpack("N","\0$len");
            push @msg,[ $ht,substr($buf,0,$len,'') ];
            _v_print sprintf("...ssl received type=%d ver=0x%x ht=0x%x size=%d", $type,$ver,$ht,length($msg[-1][1]));
        }
    } else {
        @msg = $buf;
        _v_print sprintf("...ssl received type=%d ver=%x size=%d", $type,$ver,length($buf));
    }
    return ($type,$ver,@msg);
} # _readframe
sub _isbleed($$)        {
    #? return "heartbleed" if target supports TLS extension 15 (heartbeat), empty string otherwise
    # SEE Note:heartbleed
    my ($host, $port) = @_;
    my $heartbeats    = 1;
    my $cl  = undef; # TODO: =$Net::SSLinfo::socket;
    my $ret = "";       # empty string as required in %checks
    my ($type,$ver,$buf,@msg) = ("", "", "", ());
    local $\ = undef;   # take care, must not be \n !!

        # open our own connection and close it at end
# TODO: does not work with socket from SSLinfo.pm
# TODO: following unless{}else{} should be same as in _usesocket()
    unless (($cfg{'starttls'}) || (($cfg{'proxyhost'})&&($cfg{'proxyport'}))) {
        # no proxy and not starttls
        $cl = IO::Socket::INET->new(PeerAddr=>"$host:$port", Timeout=>$cfg{'timeout'}) or do {
            _warn("321: _isbleed: failed to connect: '$!'");
            _trace("_isbleed: fatal exit in IO::Socket::INET->new\n");
            return "failed to connect";
        };
    } else {
        # proxy or starttls
        _trace("_isbleed: using 'Net::SSLhello'");
        $cl = Net::SSLhello::openTcpSSLconnection($host, $port);
        if ((not defined $cl) || ($@)) { # No SSL Connection
            local $@ = " Did not get a valid SSL-Socket from Function openTcpSSLconnection -> Fatal Exit of openTcpSSLconnection" unless ($@);
            _warn ("322: _isbleed (with openTcpSSLconnection): $@\n");
            _trace("_isbleed: fatal exit in _doCheckSSLciphers\n");
            return("failed to connect");
        }
        # NO SSL upgrade needed -> NO else
    }

    # all following code stolen from Steffen Ullrich (08. April 2014):
    #   https://github.com/noxxi/p5-scripts/blob/master/check-ssl-heartbleed.pl
    # code slightly adapted to our own variables: $host, $port, $cfg{'timeout'}
    # also die() replaced by _warn()

    # client hello with heartbeat extension
    # taken from http://s3.jspenguin.org/ssltest.py
    print $cl pack("H*",join('',qw(
                    16 03 02 00  dc 01 00 00 d8 03 02 53
        43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
        bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
        00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
        00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
        c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
        c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
        c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
        c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
        00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
        03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
        00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
        00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
        00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
        00 0f 00 01 01
    )));
    while (1) {
        ($type,$ver,@msg) = _readframe($cl) or do {
            #ORIG die "no reply";
            _warn("323: isbleed: no reply: '$!'");
            _hint("server does not respond, this does not indicate that it is not vulnerable!");
            return "no reply";
        };
        last if $type == 22 and grep { $_->[0] == 0x0e } @msg; # server hello done
    }
    # heartbeat request with wrong size
    for(1..$heartbeats) {
        _v_print("...send heartbeat#$_");
        print $cl pack("H*",join('',qw(18 03 02 00 03 01 40 00)));
    }
    if ( ($type,$ver,$buf) = _readframe($cl)) {
        if ( $type == 21 ) {
            _v_print("received alert (probably not vulnerable)");
        } elsif ( $type != 24 ) {
            _v_print("unexpected reply type $type");
        } elsif ( length($buf)>3 ) {
            $ret = "heartbleed";
            _v_print("BAD! got ".length($buf)." bytes back instead of 3 (vulnerable)");
            #show_data($buf) if $show;
            #if ( $show_regex ) {
            #    while ( $buf =~m{($show_regex)}g ) {
            #        print STDERR $1."\n";
            #    }
            #}
            # exit 1;
        } else {
            _v_print("GOOD proper heartbeat reply (not vulnerable)");
        }
    } else {
        _v_print("no reply - probably not vulnerable");
    }
    close($cl);
    _trace("_isbleed= $ret\n");
    return $ret;
} # _isbleed

sub _isccs($$$)         {
    #? return "ccs" if target is vulnerable to CCS Injection, empty string otherwise
    # parameter $ssl must be provided as binary value: 0x00, 0x01, 0x02, 0x03 or 0x04
    # http://ccsinjection.lepidum.co.jp/
    # inspired by http://blog.chris007.de/?p=238
    my ($host, $port, $ssl) = @_;
    my $heartbeats    = 1;
    my $cl  = undef; # TODO: =$Net::SSLinfo::socket;
    my $ret = "";       # empty string as required in %checks
    my ($type,$ver,$buf,@msg) = ("", "", "", ());
    undef $\;           # take care, must not be \n !!

        # open our own connection and close it at end
# TODO: does not work with socket from SSLinfo.pm
    $cl = IO::Socket::INET->new(PeerAddr => "$host:$port", Timeout => $cfg{'timeout'}) or  do {
        _warn("331: _isccs: failed to connect: '$!'");
        return "failed to connect";
    };
#################
# $ccs = _isccs($host, $port, $ssl);
#    'openssl_version_map' => {  # map our internal option to openssl version (hex value)
#        'SSLv2'=> 0x0002, 'SSLv3'=> 0x0300, 'TLSv1'=> 0x0301, 'TLSv11'=> 0x0302, 'TLSv12'=> 0x0303, 'TLSv13'=> 0x0304,  }
#################
#\x14\x03\tls_version\x00\x01\x01    sed 's/tls_version/'"$2"'/g'
#\x01    # ist TLSv1
# 14 03 01 00 01 01
    # client hello with CCS
    #   00..00  # random 32 byte (i.e. Unix time)
    #   00      # Session ID length
    #   00 68   # Cipher suites length
    print $cl pack("H*",join('',qw(
        53 9c b2 cb 4b 42 f9 2d  0b e5 9c 21 f5 a3 89 ca
        7a d9 b4 ab 3f d3 22 21  5e c4 65 0d 1e ce ed c2
        00
        00 68
        c0 13 c0 12 c0 11 c0 10  c0 0f c0 0e c0 0d c0 0c
        c0 0b c0 0a c0 09 c0 08  c0 07 c0 06 c0 05 c0 04
        c0 03 c0 02 c0 01 00 39  00 38 00 37 00 36 00 35
        00 34 00 33 00 32 00 31  00 30 00 2f 00 16 00 15
        00 14 00 13 00 12 00 11  00 10 00 0f 00 0e 00 0d
        00 0c 00 0b 00 0a 00 09  00 08 00 07 00 06 00 05
        00 04 00 03 00 02 00 01  01 00
    )));
    while (1) {
        ($type,$ver,@msg) = _readframe($cl) or do {
            _warn("332: _isccs: no reply: '$!'");
            return "no reply";
        };
        last if $type == 22 and grep { $_->[0] == 0x0e } @msg; # server hello done
    }
    if ( ($type,$ver,$buf) = _readframe($cl)) {
        if ( $type == 21 ) {
            _v_print("received alert (probably not vulnerable)");
        } elsif ( $type != 24 ) {
            _v_print("unexpected reply type $type");
        } elsif ( length($buf)>3 ) {
            $ret = "heartbleed";
            _v_print("BAD! got ".length($buf)." bytes back instead of 3 (vulnerable)");
            #show_data($buf) if $show;
            #if ( $show_regex ) {
            #    while ( $buf =~m{($show_regex)}g ) {
            #        print STDERR $1."\n";
            #    }
            #}
            # exit 1;
        } else {
            _v_print("GOOD proper heartbeat reply (not vulnerable)");
        }
    } else {
        _v_print("no reply - probably not vulnerable");
    }
    close($cl);
    return $ret;
} # _isccs

sub _isbeastskipped($$) {
    #? returns protocol names if they are vulnerable to BEAST but the check has been skipped,
    #? returns empty string otherwise.
    my ($host, $port) = @_;
    my @ret;
    foreach my $ssl (qw(SSLv2 SSLv3 TLSv1)) {
        # If $cfg{$ssl}=0, the check may be disabled, i.e. with --no-sslv3 .
        if ($cfg{$ssl} == 0) {
            push(@ret, _get_text('disabled', "--no-$ssl"));
        }
    }
#_dbx ": TLS  " . join(" ", @ret);
    return join(" ", @ret);
} # _isbeastskipped

sub _istls12only($$)    {
# NOTE: not yet used
    #? returns empty string if TLS 1.2 is the only protocol used,
    #? returns all used protocols otherwise
    my ($host, $port) = @_;
    my @ret;
    foreach my $ssl (qw(SSLv2 SSLv3 TLSv1 TLSv11)) {
        # If $cfg{$ssl}=0, the check may be disabled, i.e. with --no-sslv3 .
        # If the protocol  is supported by the target,  at least  one cipher
        # must be accpted. So the amount of ciphers must be > 0.
        if ($prot{$ssl}->{'cnt'}  >  0) {
            push(@ret, $ssl);
        }
        if ($cfg{$ssl} == 0) {
            # this condition is never true if ciphers have been detected
            push(@ret, _get_text('disabled', "--no-$ssl"));
        }
    }
#_dbx ": TLS  " . join(" ", @ret);
    return join(" ", @ret);
} # _istls12only

sub _is_ssl_error($$$)  {
    # returns 1 if probaly a SSL connection error occoured; 0 otherwise
    # increments counters in $cfg{'done'}
    my ($anf, $end, $txt) = @_;
    return 0 if (($end - $anf) <= $cfg{'sslerror'}->{'timeout'});
    $cfg{'done'}->{'ssl_errors'}++; # total counter
    $cfg{'done'}->{'ssl_failed'}++; # local counter
    return 0 if ($cfg{'ssl_error'} <= 0);   # no action required
    if ($cfg{'done'}->{'ssl_errors'} > $cfg{'sslerror'}->{'total'}) {
        _warn("301: $txt after $cfg{'sslerror'}->{'total'} total errors");
        _hint("use  --no-ssl-error  or  --ssl-error-max=  to continue connecting");
        return 1;
    }
    if ($cfg{'done'}->{'ssl_failed'} > $cfg{'sslerror'}->{'max'}) {
        _warn("302: $txt after $cfg{'sslerror'}->{'max'} max errors");
        _hint("use  --no-ssl-error  or  --ssl-error-max=  to continue connecting");
        return 1;
    }
    return 0;
} # _is_ssl_error

sub _checkwildcard($$)  {
    # compute usage of wildcard in CN and subjectAltname
    my ($host, $port) = @_;
    my ($cn_host, $rex);
    $cn_host = $data{'cn'}->{val}($host);
    $checks{'wildcard'}->{val} = "<<CN:>>$cn_host" if ($cn_host =~ m/[*]/);
    foreach my $value (split(" ", $data{'altname'}->{val}($host))) {
            $value =~ s/.*://;      # strip prefix, like DNS:
        if ($value =~ m/\*/) {      # * can be anywhere, like a.b*.some.tld
            # NOTE: lazy check, because *.b*.some.tld is invalid, but works here
            $checks{'wildcard'}->{val} .= " " . $value;
            ($rex = $value) =~ s/[*]/[^.]*/;# make RegEx
                # RegEx: missing dots is ok, like a.b.some.tld
                # RegEx: leading dot is ok, like .some.tld
                # then $host must match completely ^$rex$
            $checks{'wildhost'}->{val}  = $value if ($host =~ m/^$rex$/);
            $checks{'cnt_wildcard'}->{val}++;
        }
        $checks{'cnt_altname'}->{val}++;
        $checks{'len_altname'}->{val} = length($value) + 1; # count number of characters + type (int)
    }
    # checking for SNI does not work here 'cause it destroys %data
    return;
} # _checkwildcard

sub _can_connect        {
    # return 1 if host:port can be connected; 0 otherwise
    my ($host, $port, $sni, $timeout, $ssl) = @_;
    local $? = 0; local $! = undef;
    my $socket;
    if ($ssl == 1) {    # need different method for connecting with SSL
        #dbx# use IO::Socket::SSL qw/debug3/;
        # simple connect: do not verify the certificate and/or CRL, OCSP, which
        # may result in a connection fail
        $socket = IO::Socket::SSL->new(
            PeerAddr    => "127.0.0.2",
            PeerPort    => $port,
            Proto       => "tcp",
            SSL_verify_mode => 0x0, # SSL_VERIFY_NONE => Net::SSLeay::VERIFY_NONE(); # 0
            SSL_check_crl   => 0,   # do not check CRL
            Timeout     => $timeout,
            SSL_hostname => $sni,
        ) or do { _v_print("_can_connect: IO::Socket::SSL->new(): $! #" .  IO::Socket::SSL::errstr()); };
    } else {
        $socket = IO::Socket::INET->new(
            PeerAddr    => $host,
            PeerPort    => $port,
            Proto       => "tcp",
            Timeout     => $timeout,
        ) or do { _v_print("_can_connect: IO::Socket::INET->new(): $!"); };  # IO::Socket::INET::errstr();
    }
    if (defined $socket) {
        close($socket);
        return 1;
    }
    _warn("324: failed to connect target $host:$port : '$!'");
    return 0;
} # _can_connect

sub _usesocket($$$$)    {
    # return protocol and cipher accepted by SSL connection
    # should return the target's prefered cipher if none are given in $ciphers
    # NOTE that this function is used to check for supported ciphers only,
    # hence no need for sophisticated options in new() and no certificate
    # checks, $ciphers must be colon (:) separated list
    my ($ssl, $host, $port, $ciphers) = @_;
    my $cipher  = "";   # to be returned
    my $sni     = ($cfg{'usesni'}  < 1) ? "" : $host;
    my $npns    = ($cfg{'usenpn'}  < 1) ? [] : $cfg{'cipher_npns'};
    my $alpns   = ($cfg{'usealpn'} < 1) ? [] : $cfg{'cipher_alpns'};
        # --no-alpn or --no-npn is same as --cipher-alpn=, or --cipher-npn=,
    my $version = "";   # version returned by IO::Socket::SSL-new
    my $sslsocket = undef;
    # TODO: dirty hack (undef) to avoid Perl error like:
    #    Use of uninitialized value in subroutine entry at /usr/share/perl5/IO/Socket/SSL.pm line 562.
    # which may occour if Net::SSLeay was not build properly with support for
    # these protocol versions. We only check for SSLv2 and SSLv3 as the *TLSx
    # doesn't produce such warnings. Sigh.
    _trace1("_usesocket($ssl, $host, $port, $ciphers){ sni: $sni");
    # _warn_nosni(); # not here, because too noisy
    # following ugly if conditions: because one or both functions may be there
    if (($ssl eq "SSLv2") && (not defined &Net::SSLeay::CTX_v2_new)) {
        _warn("303: SSL version '$ssl': not supported by Net::SSLeay");
        return "";
    }
    if (($ssl eq "SSLv3") && (not defined &Net::SSLeay::CTX_v3_new)) {
        _warn("304: SSL version '$ssl': not supported by Net::SSLeay");
        return "";
    }
    # FIXME: use Net::SSLeay instead of IO::Socket::SSL
    if (eval {  # FIXME: use something better than eval()
        # TODO: eval necessary to avoid Perl error like:
        #   invalid SSL_version specified at /usr/share/perl5/IO/Socket/SSL.pm line 492.
        # TODO: SSL_hostname does not support IPs (at least up to 1.88); check done in IO::Socket::SSL
        #dbx# $IO::Socket::SSL::DEBUG = 1;
        unless (($cfg{'starttls'}) || (($cfg{'proxyhost'})&&($cfg{'proxyport'}))) {
            # no proxy and not starttls
            _trace1("_usesocket: using 'IO::Socket::SSL' with '$ssl'");
            local $? = 0; local $! = undef;
            $sslsocket = IO::Socket::SSL->new(
                PeerAddr        => $host,
                PeerPort        => $port,
                Proto           => "tcp",
                Timeout         => $cfg{'timeout'},
                SSL_hostname    => $sni,    # for SNI
                SSL_verify_mode => 0x0,     # SSL_VERIFY_NONE => Net::SSLeay::VERIFY_NONE(); # 0
                SSL_ca_file     => undef,   # see man IO::Socket::SSL ..
                SSL_ca_path     => undef,   # .. newer versions are smarter and accept ''
                SSL_check_crl   => 0,       # do not check CRL
                SSL_version     => $ssl,    # default is SSLv23 (for empty $ssl)
                SSL_cipher_list => $ciphers,
                SSL_ecdh_curve  => "prime256v1",     # OID or NID; ecdh_x448, default is prime256v1, ecdh_x25519
                #SSL_ecdh_curve  => $cfg{'ciphercurves'},# OID or NID; ecdh_x448, default is prime256v1,
                #SSL_ecdh_curve  => [qw(sect163k1 x25519)],
                #TODO: SSL_ecdh_curve  => undef,     # TODO: cannot be selected by options
                SSL_alpn_protocols  => $alpns,
                SSL_npn_protocols   => $npns,
                #TODO: SSL_honor_cipher_order  => 1,   # usefull for SSLv2 only
                #SSL_check_crl   => 1,       # if we want to use a client certificate
                #SSL_cert_file   => "path"   # file for client certificate
            );
            #_trace1("_usesocket: IO::Socket::SSL->new: $? : $! :");
        } else {
            # proxy or starttls
            _trace1("_usesocket: using 'Net::SSLhello'");
            local $? = 0; local $! = undef;
            $sslsocket = Net::SSLhello::openTcpSSLconnection($host, $port);
            if ((not defined ($sslsocket)) || ($@)) { # No SSL Connection
                local $@ = " Did not get a valid SSL-Socket from Function openTcpSSLconnection -> Fatal Exit" unless ($@);
                _warn("305: _usesocket: openTcpSSLconnection() failed: $@\n");
                return ("");
            } else {
                # SSL upgrade
                _trace1("_usesocket: start_SSL ($host, $port, $ciphers)\t= $cipher");
                IO::Socket::SSL->start_SSL($sslsocket,
                  Timeout         => $cfg{'timeout'},
                  SSL_hostname    => $sni,    # for SNI
                  SSL_verify_mode => 0x0,     # SSL_VERIFY_NONE => Net::SSLeay::VERIFY_NONE(); # 0
                  SSL_ca_file     => undef,   # see man IO::Socket::SSL ..
                  SSL_ca_path     => undef,   # .. newer versions are smarter and accept ''
                  SSL_check_crl   => 0,       # do not check CRL
                  SSL_version     => $ssl,    # default is SSLv23
                  SSL_cipher_list => $ciphers,
                  SSL_ecdh_curve  => "prime256v1", # default is prime256v1,
                  SSL_alpn_protocols => $alpns,
                  SSL_npn_protocols  => $npns,
                ) or do {
                    _trace1("_usesocket: ssl handshake failed: $!");
                    return "";
                };
            }
        }
        #dbx# _dbx("_usesocket: $? : $! : $IO::Socket::SSL::SSL_ERROR :"); # more info in rare cases
    }) {        # eval succeded
        if ($sslsocket) {
            # SEE Note:Selected Protocol
            $version = $sslsocket->get_sslversion() if ($IO::Socket::SSL::VERSION > 1.964);
            $cipher  = $sslsocket->get_cipher();
            $sslsocket->close(SSL_ctx_free => 1);
            _trace1("_usesocket: SSL version (for $ssl $ciphers): $version");
        }
    } else {    # eval failed: connect failed
        # we may get hints in $! like:
        #   * empty if cipher was not accepted
        #   * contains an error string if the connection was rejected or there
        #     was an error in IO::Socket::SSL (i.e. timeout)
        _trace1("_usesocket: connection failed (for $ssl $ciphers): $!");
    }
    _trace1("_usesocket()\t= $cipher }");
    return $version, $cipher;
} # _usesocket

sub _useopenssl($$$$)   {
    # return cipher accepted by SSL connection
    # should return the target's prefered cipher if none are given in $ciphers
    # $ciphers must be colon (:) separated list
    # adds all configured options, like -alpn -curves -servername etc. with
    # their proper values
    my ($ssl, $host, $port, $ciphers) = @_;
    my $msg  =  $cfg{'openssl_msg'};
    my $sni  = ($cfg{'usesni'} == 1) ? "-servername $host" : "";
    $ciphers = ($ciphers      eq "") ? "" : "-cipher $ciphers";
    my $curves  = "-curves " . join(":", $cfg{'ciphercurves'}); # TODO: add to command below
    _trace1("_useopenssl($ssl, $host, $port, $ciphers)"); # no { in comment here
    $ssl = ($cfg{'openssl_option_map'}->{$ssl} || '');  # set empty if no protocol given
    my $data = Net::SSLinfo::do_openssl("s_client $ssl $sni $msg $ciphers ", $host, $port, '');
# TODO: hier -alpn $protos_alpn und -nextprotoneg $protos_npn übergeben
# TODO: dann entsprechenden Code in Net::SSLinfo::do_openssl() entfernen
    # we may get for success:
    #   New, TLSv1/SSLv3, Cipher is DES-CBC3-SHA
    # also possible would be Cipher line from:
    #   SSL-Session:
    #       Protocol  : TLSv1.2
    #       Cipher    : DES-CBC3-SHA
    _trace2("_useopenssl: data #{ $data }");
    return "", "", "" if ($data =~ m#New,.*?Cipher is .?NONE#);

    my $version = $data;# returned version
       $version =~ s#^.*[\r\n]+ +Protocol\s*:\s*([^\r\n]*).*#$1#s;
    my $cipher  = $data;
    if ($cipher =~ m#New, [A-Za-z0-9/.,-]+ Cipher is#) {
        $cipher =~ s#^.*[\r\n]+New,\s*##s;
        $cipher =~ s#[A-Za-z0-9/.,-]+ Cipher is\s*([^\r\n]*).*#$1#s;
        my $dh  = get_dh_paramter($cipher, $data);
        _trace1("_useopenssl()\t= $cipher $dh }");
        return $version, $cipher, $dh;
    }
    # else check for errors ...

    # grrrr, it's a pain that openssl changes error messages for each version
    # we may get any of following errors:
    #   TIME:error:140790E5:SSL routines:SSL23_WRITE:ssl handshake failure:.\ssl\s23_lib.c:177:
    #   New, (NONE), Cipher is (NONE)
    #   connect:errno=11004
    #   TIME:error:14077410:SSL routines:SSL23_GET_SERVER_HELLO:sslv3 alert handshake failure:s23_clnt.c:602:
    #   TIME:error:140740B5:SSL routines:SSL23_CLIENT_HELLO:no ciphers available:s23_clnt.c:367:
    # if SSL version not supported (by openssl):
    #   29153:error:140A90C4:SSL routines:SSL_CTX_new:null ssl method passed:ssl_lib.c:1453:
    # openssl 1.0.1e :
    #   # unknown messages: 139693193549472:error:1407F0E5:SSL routines:SSL2_WRITE:ssl handshake failure:s2_pkt.c:429:
    #   error setting cipher list
    #   139912973481632:error:1410D0B9:SSL routines:SSL_CTX_set_cipher_list:no cipher match:ssl_lib.c:1314:
    return "", "", "" if ($data =~ m#SSL routines.*(?:handshake failure|null ssl method passed|no ciphers? (?:available|match))#); ## no critic qw(RegularExpressions::ProhibitComplexRegexes)

    if ($data =~ m#^\s*$#) {
        _warn("311: SSL version '$ssl': empty result from openssl");
    } else {
        _warn("312: SSL version '$ssl': unknown result from openssl");
        _warn("312: result from openssl: '$data'") if ($cfg{'verbose'} > 0);
    }
    _trace2("_useopenssl: #{ $data }");
    if ($cfg{'verbose'} < 1) {
        _hint("use options like: --v --trace"); # print always
    } else {
        _v_print("_useopenssl: Net::SSLinfo::do_openssl() #{\n$data\n#}");
    }

    return "", "", "";
} # _useopenssl

sub _get_ciphers_range  {
    #? retrun array of cipher-suite hex values for given range
    #  uses $cfg{'cipherranges'}->{$range}
    my $ssl   = shift;
    my $range = shift;
       $range = 'SSLv2' if ($ssl eq 'SSLv2');   # but SSLv2 needs its own list
    my @all;
    _trace("_get_ciphers_range($ssl, $range");
    #  NOTE: following eval must not use the block form because the
    #        value needs to be evaluated
    foreach my $c (eval($cfg{'cipherranges'}->{$range}) ) { ## no critic qw(BuiltinFunctions::ProhibitStringyEval)
        push(@all, sprintf("0x%08X",$c));
    }
    _trace2("_get_ciphers_range: @all");
    return @all;
} # _get_ciphers_range

sub _get_ciphers_list   {
    #? return space-separated list of cipher suites according command line options
    _trace("_get_ciphers_list(){");
    my @ciphers = ();
    my $range   = $cfg{'cipherrange'};  # default is 'rfc'
    _trace("cipherpattern= $cfg{'cipherpattern'}, cipherrange= $range");
    my $pattern = $cfg{'cipherpattern'};# default pattern (colon-separated)
       $pattern = join(":", @{$cfg{'cipher'}}) if (scalar(@{$cfg{'cipher'}}) > 0);
        # @{$cfg{'cipher'}}) > 0  if option --cipher=* was used
        # can be specified like: --cipher=NULL:RC4  or  --cipher=NULL --cipher=RC4
    _trace(" cipher pattern= $pattern");
    if ($range eq "rfc") {
        # default cipher range is 'rfc' (see o-saft-lib.pm), then get list of
        # ciphers from Net::SSLinfo
        if ($cmd{'extciphers'} == 1) {
            @ciphers = Net::SSLinfo::cipher_openssl($pattern);
        } else {
            @ciphers = Net::SSLinfo::cipher_list(   $pattern);
        }
    } else {
        # cipher range specified with --cipher-range=* option
        # ranges are defined as numbers, need to get the cipher suite name
        _v_print("cipher range: $range");
        foreach my $c (eval($cfg{'cipherranges'}->{$range}) ) { ## no critic qw(BuiltinFunctions::ProhibitStringyEval)
            my $key = sprintf("0x%08X",$c);
            _trace($key,   get_cipher_suitename($key));
            push(@ciphers, get_cipher_suitename($key));
        }
    }
    _trace(" got ciphers: @ciphers");
    if (@ciphers <= 0) {      # empty list
        _warn("063: given pattern '$pattern' did not return cipher list");
        _y_CMD("  using private cipher list ...");
        @ciphers = keys %ciphers;
    }
    if (@ciphers <= 0) {
        print "Errors: " . Net::SSLinfo::errors();
        die STR_ERROR, "014: no ciphers found; may happen with openssl pre 1.0.0 according given pattern";
    }
    @ciphers    = grep{!/^\s*$/} @ciphers;   # remove empty names
    _trace("_get_ciphers_list\t= @ciphers }"); # TODO: trace a bit late
    return @ciphers;
} # _get_ciphers_list

sub _get_default($$$$)  {
    # return list of offered (default) cipher from target
    # mode defines how to retrieve the prefered cipher
    #   strong:  pass cipher list sorted with strongest first
    #   weak:    pass cipher list sorted with weakest first
    #   default: pass no cipher list which then uses system default

    # To get the target's prefered cipher, all known ciphers are send so that
    # the target should select the most secure one.
    # Both, openssl and sockets (IO::Socket::SSL), use the underlaying libssl
    # which works with the compiled in ciphers only.  Hence all known ciphers
    # (by libssl) are passed:  @{$cfg{'ciphers'}}, we cannot pass all ciphers
    # like: keys %ciphers . +cipherraw command must be used, if other ciphers
    # than the local available should be checked.

    my ($ssl, $host, $port, $mode) = @_;
    _trace("_get_default($ssl, $host, $port, $mode){");
    $cfg{'done'}->{'default_get'}++;
    my $dh      = "";   # returned DH parameters (not yet used)
    my $version = "";   # returned protocol version
    my $cipher  = "";
    my @list = ();   # mode == default
       @list =         sort_cipher_names(@{$cfg{'ciphers'}}) ;#if ($mode eq 'strong');
       @list = reverse sort_cipher_names(@{$cfg{'ciphers'}}) if ($mode eq 'weak');
    my $cipher_list = join(":", @list);

    if (0 == $cmd{'extciphers'}) {
        ($version, $cipher)     = _usesocket( $ssl, $host, $port, $cipher_list);
    } else { # force openssl
        ($version, $cipher, $dh)= _useopenssl($ssl, $host, $port, $cipher_list);
           # NOTE: $ssl will be converted to corresponding option for openssl,
           # for example: DTLSv1 becomes -dtlsv1
           # Unfortunately openssl (or Net::SSLinfo) returns a cipher even if
           # the protocoll is not supported. Reason (aka bug) yet unknown.
           # Hence the caller should ensure that openssl supports $ssl .
    }

    $cipher = "" if not defined $cipher;
    if ($cipher =~ m#^\s*$#) {
        my $txt = "SSL version '$ssl': cannot get prefered cipher; ignored";
        # SSLv2 is special, see _usesocket "dirty hack"; don't print
        _v_print($txt) if ($ssl !~ m/SSLv[2]/);
    } else {
        _v2print("prefered cipher: $ssl:\t$cipher");
    }
    _trace("_get_default()\t= $cipher }"); # TODO: trace a bit late
    return $cipher;
} # _get_default

sub _get_data0          {
    #? get %data for connection without SNI
    my ($host, $port) = @_;
    _y_CMD("test without SNI (disable with --no-sni) ...");
    # check if SNI supported, also copy some data to %data0
        # to do this, we need a clean SSL connection with SNI disabled
        # see SSL_CTRL_SET_TLSEXT_HOSTNAME in NET::SSLinfo
        # finally we close the connection to be clean for all other tests
    _trace(" cn_nosni: {");
    _yeast_TIME("no SNI{");
    $Net::SSLinfo::use_SNI  = 0;    # no need to save current value
    if (defined Net::SSLinfo::do_ssl_open(
                    $host, $port,
                    (join(" ", @{$cfg{'version'}})),
                     join(" ", @{$cfg{'ciphers'}}))
       ) {
        _y_CMD("  open with no SNI.");
        _trace("cn_nosni: method: $Net::SSLinfo::method");
        $data{'cn_nosni'}->{val}        = $data{'cn'}->{val}($host, $port);
        $data0{'session_ticket'}->{val} = $data{'session_ticket'}->{val}($host);
# TODO:  following needs to be improved, because there are multipe openssl
        # calls which may produce unexpected results (10/2015) {
        foreach my $key (keys %data) { # copy to %data0
            next if ($key =~ m/$cfg{'regex'}->{'commands-INT'}/i);
            $data0{$key}->{val} = $data{$key}->{val}($host, $port);
        }
# }
    } else {
        _warn("204: Can't make a connection to $host:$port without SNI; no initial data (compare with and without SNI not possible)");
    }
    _yeast_TIME("no SNI}");
    # now close connection, which also resets Net::SSLinfo's internal data
    # structure,  Net::SSLinfo::do_ssl_close() is clever enough to work if
    # the connection failed and does nothing (except resetting data)
    if ($cfg{'verbose'} >  0) {
        _warn("206: $_") foreach Net::SSLinfo::errors();
    }
    Net::SSLinfo::do_ssl_close($host, $port);
    $Net::SSLinfo::use_SNI  = $cfg{'sni_name'};
    _trace(" cn_nosni: $data{'cn_nosni'}->{val}  }");
    return;
} # _get_data0

sub ciphers_scan_prot   {
    #? test target if given ciphers are accepted, returns array of accepted ciphers
    #? scans for ciphers with given protocol only
    my ($ssl, $host, $port, $arr) = @_;
    my @ciphers = @{$arr};  # ciphers to be checked
    my $version = "";       # returned protocol version
    my $dh      = "";       # returned DH parameters (not yet used)

    _trace("ciphers_scan_prot($ssl, $host, $port, @ciphers){");
    my @res     = ();       # return accepted ciphers
    $cfg{'done'}->{'ssl_failed'} = 0;   # SEE Note:--ssl-error
    _v_print("connect delay: $cfg{'connect_delay'} second(s)") if ($cfg{'connect_delay'} > 0);
    my $cnt     = 0;
    foreach my $c (@ciphers) {
        next if ($c =~ m/^\s*$/);
        my $anf = time();
        my $supported = "";
        $cnt++;
        my $txt = "$ssl: ($cnt of " . scalar(@ciphers) . " ciphers checked) abort connection attempts";
        printf("#   cipher %3d/%d %s%s\r", $cnt, scalar @ciphers, $c, " "x42) if ($cfg{'verbose'} > 0);
            # no \n at end of line, hence all messages print to same line
            # wipe previous trailing text with  " "x42
            # cannot use _v_print() because it prints with \n
        if (0 == $cmd{'extciphers'}) {
            if (0 >= $cfg{'cipher_md5'}) {
                # Net::SSLeay:SSL supports *MD5 for SSLv2 only
                # detailled description see OPTION  --no-cipher-md5
                #_hint("--no-cipher-md5 can be used to disable checks with MD5 ciphers");
                _v4print("check cipher (MD5): $ssl:$c\n");
                next if (($ssl ne "SSLv2") && ($c =~ m/MD5/));
            }
            ($version, $supported)      = _usesocket( $ssl, $host, $port, $c);
        } else { # force openssl
            ($version, $supported, $dh) = _useopenssl($ssl, $host, $port, $c);
        }
        $supported = "" if not defined $supported;
        sleep($cfg{'connect_delay'});
        last if (_is_ssl_error($anf, time(), $txt) > 0);
        if (($c !~ /(?:HIGH|ALL)/) and ($supported ne "")) { # given generic names is ok
            if (($c !~ $supported) and ($ssl ne "SSLv2")) {
                # mismatch: name asked for and name returned by server
                # this may indicate wrong cipher name in our configuration
                # or the server returned no data or closed TCP connection
                # or connection timed out, see _is_ssl_error()
                # no complain for SSLv2, which may return an empty string
                _warn("411: checked $ssl cipher '$c' does not match returned cipher '$supported'");
            }
        }
        push(@res, "$version:$supported") if ($supported ne "");
        my $yesno = ($supported eq "") ? "no" : "yes";
        _v2print("check cipher: $ssl:$c\t$yesno");
        # TODO: should close dangling sockets here
    } # foreach @ciphers
    _v_print("connection errors: $cfg{'done'}->{'ssl_errors'}                  ");
    #    spaces to overwrite remaining cipher suite names
    _trace("ciphers_scan_prot()\t= " . $#res . " @res }");
    return @res;
} # ciphers_scan_prot

sub ciphers_scan        {
    #? scan target for ciphers for all protocols
    # writes to @cipher_results
    my ($host, $port) = @_;
# FIXME: 6/2015 es kommt eine Fehlermeldung wenn openssl 1.0.2 verwendet wird:
# Use of uninitialized value in subroutine entry at /usr/share/perl5/IO/Socket/SSL.pm line 562.
# hat mit den Ciphern aus @{$cfg{'ciphers'}} zu tun
#    IDEA-CBC-MD5 RC2-CBC-MD5 DES-CBC3-MD5 RC4-64-MD5 DES-CBC-MD5 :
# Ursache in _usesocket() das benutzt IO::Socket::SSL->new()
    my $cnt = scalar(@{$cfg{'ciphers'}});
    foreach my $ssl (@{$cfg{'version'}}) {
        my $__openssl   = ($cmd{'extciphers'} == 0) ? 'socket' : 'openssl';
        if (($cfg{'verbose'} + $cfg{'trace'} + $cfg{'traceCMD'}) > 0) {
            # optimize output: instead using 3 lines with _y_CMD(), _trace() and _v_print()
            my $_me = "";
               $_me = $cfg{'mename'} . " CMD:" if ($cfg{'traceCMD'} > 0); # TODO: _yTIME() missing
               $_me = $cfg{'mename'} . "::"    if ($cfg{'trace'}    > 0);
            print("#$_me checking $cnt ciphers for $ssl ... ($__openssl)");
        }
        if ($ssl =~ m/^SSLv[23]/) {
            # SSLv2 has no SNI; SSLv3 has originally no SNI
            
            if (_is_do('cipher') or $cfg{'verbose'} > 0) {
                _warn_nosni("410:", $ssl, $cfg{'usesni'});
                # ciphers are collected for various checks, this would result
                # in above warning, even then if  SSLv3 is not needed for the
                # requested check;  to avoid these noicy warnings, it is only
                # printend for  +cipher  command or with --v option
            }
            next;
        }
        my $__verbose   = $cfg{'verbose'};
            # $cfg{'v_cipher'}  should only print cipher checks verbosely,
            # ciphers_scan_prot()  uses  $cfg{'verbose'}, hence wee need to save
            # the current value and reset after calling ciphers_scan_prot()
        $cfg{'verbose'} = 2 if ($cfg{'v_cipher'} > 0);
        my @supported = ciphers_scan_prot($ssl, $host, $port, \@{$cfg{'ciphers'}});
        $cfg{'verbose'} = $__verbose if ($__verbose != 2);
        # remove  protocol: in each item
        #foreach my $i (keys @supported) { $supported[$i] =~ s/^[^:]*://; } # for Perl > 5.12
        for my $i (0..$#supported) { $supported[$i] =~ s/^[^:]*://; }       # for Perl < 5.12 and Perl::Critic
            # map({s/^[^:]*://} @supported); # is the perlish way (all Perl 5.x)
            # but discarted by Perl::Critic, hence the less readable foreach
        foreach my $c (@{$cfg{'ciphers'}}) {  # might be done more perlish ;-)
            push(@cipher_results, [$ssl, $c, ((grep{/^$c$/} @supported)>0) ? "yes" : "no"]);
        }
    }
    return;
} # ciphers_scan

sub check_certchars($$) {
    #? check for invalid characters in certificate
    my ($host, $port) = @_;
    _y_CMD("check_certchars() ". $cfg{'done'}->{'check_certchars'});
    $cfg{'done'}->{'check_certchars'}++;
    return if ($cfg{'done'}->{'check_certchars'} > 1);
    my $value;
    my $txt;

    # check vor invald charaters
    foreach my $label (@{$cfg{'need-checkchr'}}, qw(email aux)) {
        $value = $data{$label}->{val}($host);
        if ($value ne "") {
            $checks{'nonprint'}->{val} .= " $label" if ($value =~ m/$cfg{'regex'}->{'nonprint'}/);
            $checks{'crnlnull'}->{val} .= " $label" if ($value =~ m/$cfg{'regex'}->{'crnlnull'}/);
        }
    }

    # valid characters (probably only relevant for DV and EV)
    #_dbx "EV: keys: " . join(" ", @{$cfg{'need-checkchr'}} . "extensions";
    #_dbx "EV: regex:" . $cfg{'regex'}->{'notEV-chars'};
    # not checked explicitely: CN, O, U (should already be part of others, like subject)
    foreach my $label (@{$cfg{'need-checkchr'}}, qw(extensions)) {
        $value =  $data{$label}->{val}($host);
        $value =~ s#[\r\n]##g;         # CR and NL are most likely added by openssl
        if ($value =~ m/$cfg{'regex'}->{'notEV-chars'}/) {
            $txt = _get_text('cert_chars', $label);
            $checks{'ev_chars'}->{val} .= $txt;
            $checks{'ev+'}->{val}      .= $txt;
            $checks{'ev-'}->{val}      .= $txt;
            $checks{'dv'}->{val}       .= $txt;
             if ($cfg{'verbose'} > 0) {
                 $value =~ s#($cfg{'regex'}->{'EV-chars'}+)##msg;
                 _v2print("EV:  wrong characters in $label: $value");
             }
        }
    }

    return;
} # check_certchars

sub check_dh($$)    {
    #? check if target is vulnerable to Logjam attack; uses @cipher_results
    my ($host, $port) = @_;
    _y_CMD("check_dh() ". $cfg{'done'}->{'check_dh'});
    $cfg{'done'}->{'check_dh'}++;
    return if ($cfg{'done'}->{'check_dh'} > 1);

    # Logjam check is a bit ugly: DH Parameter may be missing
    # TODO: implement own check for DH parameters instead relying on openssl
    my $txt = $data{'dh_parameter'}->{val}($host);
    if ($txt eq "") {
        $txt = "<<openssl did not return DH Paramter>>";
        checkciphers($host, $port, @cipher_results); # need EXPORT ciphers fot logjam
        # TODO: calling checkciphers() is bad, it may even not contain ciphers
        my $exp = $checks{'logjam'}->{val};
        $checks{'logjam'}->{val}   .=  $txt;
        $checks{'logjam'}->{val}   .=  "; but has WEAK ciphers: $exp" if ($exp ne "");
        $checks{'dh_512'}->{val}    =  $txt;
        $checks{'dh_2048'}->{val}   =  $txt;
        $checks{'ecdh_256'}->{val}  =  $txt;
        $checks{'ecdh_512'}->{val}  =  $txt;
        return; # no more checks possible
    }
    my $dh  = $txt;
       $dh  =~ s/.*?[^\d]*(\d+) *bits.*/$1/i;   # just get number
       # DH, 512 bits
       # DH, 1024 bits
       # DH, 2048 bits
       # ECDH, P-256, 128 bits
       # ECDH, P-256, 256 bits
       # ECDH, P-384, 384 bits
       # TODO: ECDH should also have 256 bits or more
    if ($dh =~ m/^\d+$/) {      # a number, check size
        if ($txt !~ m/ECDH/) {
            $checks{'dh_512'}->{val}    =  $txt if ($dh < 512);
            $checks{'dh_2048'}->{val}   =  $txt if ($dh < 2048);
        } else {                # ECDH is different
            $checks{'ecdh_256'}->{val}  =  $txt if ($dh < 256);
            $checks{'ecdh_512'}->{val}  =  $txt if ($dh < 512);
        }
        # lazy check: logjam if bits < 256 only
        my $val = $checks{'dh_512'}->{val} . $checks{'dh_2048'}->{val} . $checks{'ecdh_256'}->{val};
        $checks{'logjam'}->{val} = $val if ($val ne "");
    } else {                    # not a number, probably suspicious
        $checks{'logjam'}->{val}=  $txt;
    }
    return;
} # check_dh

sub check_url($$)   {
    #? request given URL and check if it is a valid CRL or OCSP site
    #? returns result of check; empty string if anything OK
    my ($uri, $type) = @_;  # type is 'ext_crl' or 'ocsp_uri'
    _y_CMD("check_url() ". $cfg{'done'}->{'check_url'});
    $cfg{'done'}->{'check_url'}++;
    _trace("check_url($uri, $type)");

    return " " if ($uri =~ m#^\s*$#);  # no URI, no more checks

    # Net::SSLeay::get_http() is used as we already include Net::SSLeay
    # NOTE: must be rewritten if Net::SSLeay is removed

    # Note: all following examples show only the headers checked herein
    # for CRL  we expect something like:
    # example: http://crl.entrust.net/level1k.crl
    #     HTTP/1.1 200 OK
    #     Accept-Ranges: bytes
    #     Content-Type: application/x-pkcs7-crl
    #     Content-Length: 1101367
    #
    # example: http://pki.google.com/GIAG2.crl
    #     HTTP/1.1 200 OK
    #     Accept-Ranges: none
    #     Transfer-Encoding: chunked
    #     Content-Type: application/pkix-crl
    #
    # bad example: http://pki.google.com
    #     HTTP/1.1 200 OK
    #     Accept-Ranges: none
    #     Transfer-Encoding: chunked
    #     Content-Type: text/html
    #
    # example: http://crl.startssl.com/crt2-crl.crl
    #     HTTP/1.1 200 OK
    #     Accept-Ranges: bytes
    #     Content-Type: application/pkix-crl
    #     Content-Length: 58411
    #
    # example: http://mscrl.microsoft.com/pki/mscorp/crl/msitwww2.crl
    #     HTTP/1.1 200 OK
    #     Content-Type: application/pkix-crl
    #     Content-Length: 179039
    #     Accept-Ranges: bytes
    #
    # for OCSP we expect something like:
    # example: http://sr.symcd.com
    #     HTTP/1.1 200 OK
    #     Content-Type: application/ocsp-response
    #     Content-Length: 5
    #     content-transfer-encoding: binary
    #
    # bad example: http://clients1.google.com/ocsp
    #     HTTP/1.1 404 Not Found
    #     Date: Sun, 17 Apr 2016 10:24:46 GMT
    #     Content-Type: text/html; charset=UTF-8
    #     Content-Length: 1565
    #
    # bad example: http://ocsp.entrust.net
    #     HTTP/1.1 200 OK
    #     Content-Type: text/html
    #     Content-Length: 68
    #
    #     meta HTTP-EQUIV="REFRESH" content="0; url=http://www.entrust.net">
    #
    # example: http://ocsp.msocsp.com
    #     HTTP/1.1 200 OK
    #     Content-Type: application/ocsp-response
    #     Content-Length: 5
    #
    # example: http://sr.symcb.com/sr.crl
    #     HTTP/1.1 200 OK
    #     Content-Type: application/pkix-crl
    #     Transfer-Encoding:  chunked
    #     Connection: Transfer-Encoding
    #
    # for AIA we expect something like:
    # example: http://www.microsoft.com/pki/mscorp/msitwww2.crt
    #      HTTP/1.1 200 OK
    #      Accept-Ranges: bytes
    #      Content-Type: application/x-x509-ca-cert
    #      Content-Length: 1418
    #

    my ($accept, $binary, $ctype, $chunk, $length);
    my $txt = "<<unexpected type: $type>>"; # this is a programming error
    my $src = 'Net::SSLeay::get_http()';
    # got an URI, extract host, port and URL
       $uri =~ m#^\s*(?:(?:http|ldap)s?:)?//([^/]+)(/.*)?$#;
      #  NOTE: it's ok here
    my $host=  $1;                          ## no critic qw(RegularExpressions::ProhibitCaptureWithoutTest)
    my $url =  $2 || "/";                   ## no critic qw(RegularExpressions::ProhibitCaptureWithoutTest)
    return "" if not defined $host;         # wrong URI may be passed
       $host=~ m#^([^:]+)(?::[0-9]{1,5})?#;
       $host=  $1;                          ## no critic qw(RegularExpressions::ProhibitCaptureWithoutTest)
    my $port=  $2 || 80;  $port =~ s/^://;  ## no critic qw(RegularExpressions::ProhibitCaptureWithoutTest)
    _trace2("check_url: get_http($host, $port, $url)");
    my ($response, $status, %headers) = Net::SSLeay::get_http($host, $port, $url,
            Net::SSLeay::make_headers('Connection' => 'close', 'Host' => $host)
    );
    _trace2("check_url: STATUS: $status");

    if ($status !~ m#^HTTP/... (?:[1234][0-9][0-9]|500) #) {
        return "<<connection to '$url' failed>>";
    }
    _trace2("check_url: header: #{ " .  join(": ", %headers) . " }"); # a bit ugly :-(
    if ($status =~ m#^HTTP/... 200 #) {
        $accept = $headers{(grep{/^Accept-Ranges$/i}     keys %headers)[0] || ""};
        $ctype  = $headers{(grep{/^Content-Type$/i}      keys %headers)[0] || ""};
        $length = $headers{(grep{/^Content-Length$/i}    keys %headers)[0] || ""};
        $binary = $headers{(grep{/^Content-transfer-encoding$/i} keys %headers)[0] || ""};
        $chunk  = $headers{(grep{/^Transfer-Encoding$/i} keys %headers)[0] || ""};
    } else {
        return "<<unexpected response: $status>>";
    }
    # FIXME: 30x status codes are ok; we should then call ourself again

    if ($type eq 'ocsp_uri') {
        _trace2("check_url: ocsp_uri ...");
        return  _get_text('invalid', "Content-Type: $ctype")   if ($ctype !~ m:application/ocsp-response:i);
        return  _get_text('invalid', "Content-Length: $ctype") if ($length < 4);
        return ""; # valid
    } # OCSP

    if ($type eq 'ext_crl') {
        _trace2("check_url: ext_crl ...");
        if ((defined $accept) && (defined $chunk)) {
            if ($accept !~ m/bytes/i) {
                if (($accept !~ m/^none/i) && ($chunk !~ m/^chunked/i)) {
                    return _get_text('invalid', "Accept-Ranges: $accept");
                }
            }
        }
        if ($ctype !~ m#application/(?:pkix-crl|x-pkcs7-crl)#i) {
                return _get_text('invalid', "Content-Type: $ctype");
        }
        return ""; # valid
    } # CRL

    return $txt;
} # check_url

sub check_nextproto {
    #? check target for ALPN or NPN support; returns list of supported protocols
    my ($host, $port, $type, $mode) = @_;
    # $type is ALPN or NPN; $mode is all or single
    # in single mode, each protocol specified in $cfg{'protos_next'} is tested
    # for its own, while in all mode all protocols are set at once
    # Also SEE Note:ALPN, NPN
    _trace("check_nextproto($host, $port, $type, $mode)");
    my @protos = split(",", $cfg{'protos_next'});
       @protos = $cfg{'protos_next'}   if ($mode eq 'all'); # pass all at once
    my @npn;
    my ($ssl, $ctx, $method);
    my $socket; # = undef;
    foreach my $proto (@protos) {
        #_trace("  do_ssl_new(..., ".(join(" ", @{$cfg{'version'}}))
        #     . ", $cfg{'cipherpattern'}, $proto, $proto, socket)");
        $ssl   = undef;
        $ctx   = undef;
        $socket= undef;
        ($ssl, $ctx, $socket, $method) = Net::SSLinfo::do_ssl_new(
                $host, $port,
                (join(" ", @{$cfg{'version'}})), $cfg{'cipherpattern'},
                (($type eq 'ALPN') ? $proto : ""),
                (($type eq 'NPN')  ? $proto : ""),
                $socket
            );
        if (not defined $ssl) {
            _warn("601: $type connection failed with '$proto'");
        } else {
            # Net::SSLeay's functions are crazy, both P_next_proto_negotiated()
            # and P_alpn_selected() return undef if not supported by server and
            # for any error. Anyway, we only want to know if $proto supported.
            # As we check protocols one by one, this information is sufficient.
            my $np;
            $np = Net::SSLeay::P_alpn_selected($ssl)         if ($type eq 'ALPN');
            $np = Net::SSLeay::P_next_proto_negotiated($ssl) if ($type eq 'NPN');
            if (defined $np && $mode eq 'single') {
                _warn("602: $type name mismatch: (send) $proto <> $np (returned)")  if ($proto ne $np);
            }
            _trace("check_nextproto: $type $np") if (defined $np) ;
            if (defined $np) {
                push(@npn, $np) if ($proto eq $np); # only if matched
            }
        }
        # TODO: need to check if ($cfg{'socket_reuse'} > 0); then do not call do_ssl_free
        Net::SSLinfo::do_ssl_free($ctx, $ssl, $socket);
        #{
        #TODO: if ($cfg(extopenssl) > 0)
        #my $data = Net::SSLinfo::do_openssl("s_client -alpn $proto -connect", $host, $port, "");
        #my $np = grep{/^ALPN protocol:.*/} split("\n", $data);
        #my $data = Net::SSLinfo::do_openssl("s_client -nextprotoneg $proto -connect", $host, $port, "");
        #my $np = grep{/^Next protocol:.*/} split("\n", $data);
        #my $np = grep{/^Protocols advertised by:.*/} split("\n", $data);
        #print "$proto : $np";
        #}
    }
    _trace("check_nextproto:  @npn");
    return @npn;
} # check_nextproto

sub checkalpn       {
    #? check target for ALPN or NPN support; returns void
    # stores list of supported protocols in corresponding $info{}
    # uses protocols from $cfg{'protos_next'} only
    my ($host, $port) = @_;
    _y_CMD("checkalpn() ");
    $cfg{'done'}->{'checkalpn'}++;
    return if ($cfg{'done'}->{'checkalpn'} > 1);
    # _trace("trace not necessary, output from check_nextproto() is sufficient");
    if ($cfg{'ssleay'}->{'get_alpn'} > 0) {
        $info{'alpns'} = join(",", check_nextproto($host, $port, 'ALPN', 'single'));
        $info{'alpn'}  = join(",", check_nextproto($host, $port, 'ALPN', 'all'));
    }
    # else warning already printed
    if ($cfg{'ssleay'}->{'get_npn'} > 0) {
        $info{'npns'}  = join(",", check_nextproto($host, $port, 'NPN',  'single'));
        $info{'npn'}   = join(",", check_nextproto($host, $port, 'NPN',  'all'));
    }
    # else warning already printed
    # TODO: 'next_protocols' should be retrieved here too
    return;
} # checkalpn

sub checkprefered   {
    #? test if target prefers strong ciphers, aka SSLHonorCipherOrder
    my ($host, $port) = @_;     # not yet used
    _y_CMD("checkprefered() " . $cfg{'done'}->{'checkprefered'});
    $cfg{'done'}->{'checkprefered'}++;
    return if ($cfg{'done'}->{'checkprefered'} > 1);
    _trace("checkprefered($host, $port){");
    foreach my $ssl (@{$cfg{'version'}}) { # check all SSL versions
        my $strong = $prot{$ssl}->{'cipher_strong'};
        my $weak   = $prot{$ssl}->{'cipher_weak'};
        my $txt = "$strong,$weak";
        $checks{'cipher_strong'}->{val} .= _prot_cipher($ssl, $txt) if ($weak ne $strong);  # FIXME: assumtion wrong if only one cipher accepted
        $checks{'cipher_order'}->{val}  .= _prot_cipher($ssl, $txt) if ($weak ne $strong);  # NOT YET USED
        $checks{'cipher_weak'}->{val}   .= _prot_cipher($ssl, $txt) if ($weak eq $strong);  # remember: eq !
    }
    _trace("checkprefered() }");
    return;
} # checkprefered

sub checkcipher($$) {
    #? test given cipher and add result to %checks and %prot
    my ($ssl, $c) = @_;
    my $risk = get_cipher_sec($c);
    # following checks add the "not compliant" or vulnerable ciphers

    # check weak ciphers
    $checks{'cipher_null'}->{val} .= _prot_cipher($ssl, $c) if ($c =~ /NULL/);
    $checks{'cipher_adh'}->{val}.= _prot_cipher($ssl, $c) if ($c =~ /$cfg{'regex'}->{'ADHorDHA'}/);
    $checks{'cipher_exp'}->{val}.= _prot_cipher($ssl, $c) if ($c =~ /$cfg{'regex'}->{'EXPORT'}/);
    $checks{'cipher_cbc'}->{val}.= _prot_cipher($ssl, $c) if ($c =~ /CBC/);
    $checks{'cipher_des'}->{val}.= _prot_cipher($ssl, $c) if ($c =~ /DES/);
    $checks{'cipher_rc4'}->{val}.= _prot_cipher($ssl, $c) if ($c =~ /$cfg{'regex'}->{'RC4orARC4'}/);
    $checks{'cipher_edh'}->{val}.= _prot_cipher($ssl, $c) if ($c =~ /$cfg{'regex'}->{'DHEorEDH'}/);
# TODO: lesen: http://www.golem.de/news/mindeststandards-bsi-haelt-sich-nicht-an-eigene-empfehlung-1310-102042.html
    # check compliance
    $checks{'ism'}->{val}       .= _prot_cipher($ssl, $c) if ($c =~ /$cfg{'regex'}->{'notISM'}/);
    $checks{'pci'}->{val}       .= _prot_cipher($ssl, $c) if ("" ne _ispci( $ssl, $c));
    $checks{'fips'}->{val}      .= _prot_cipher($ssl, $c) if ("" ne _isfips($ssl, $c));
    $checks{'rfc_7525'}->{val}  .= _prot_cipher($ssl, $c) if ("" ne _isrfc7525($ssl, $c));
    $checks{'tr_02102+'}->{val} .= _prot_cipher($ssl, $c) if ("" ne _istr02102_strict($ssl, $c));
    $checks{'tr_02102-'}->{val} .= _prot_cipher($ssl, $c) if ("" ne _istr02102_lazy(  $ssl, $c));
    $checks{'tr_03116+'}->{val} .= _prot_cipher($ssl, $c) if ("" ne _istr03116_strict($ssl, $c));
    $checks{'tr_03116-'}->{val} .= _prot_cipher($ssl, $c) if ("" ne _istr03116_lazy(  $ssl, $c));
    # check attacks
    $checks{'rc4'}->{val}        = $checks{'cipher_rc4'}->{val}; # these are the same checks
    $checks{'beast'}->{val}     .= _prot_cipher($ssl, $c) if ("" ne _isbeast($ssl, $c));
    $checks{'breach'}->{val}    .= _prot_cipher($ssl, $c) if ("" ne _isbreach($c));
    $checks{'freak'}->{val}     .= _prot_cipher($ssl, $c) if ("" ne _isfreak($ssl, $c));
    $checks{'lucky13'}->{val}   .= _prot_cipher($ssl, $c) if ("" ne _islucky($c));
    $checks{'robot'}->{val}     .= _prot_cipher($ssl, $c) if ("" ne _isrobot($ssl, $c));
    $checks{'sloth'}->{val}     .= _prot_cipher($ssl, $c) if ("" ne _issloth($ssl, $c));
    $checks{'sweet32'}->{val}   .= _prot_cipher($ssl, $c) if ("" ne _issweet($ssl, $c));
    push(@{$prot{$ssl}->{'ciphers_pfs'}}, $c) if ("" eq _ispfs($ssl, $c));  # add PFS cipher
    # counters
    $prot{$ssl}->{'-?-'}++      if ($risk =~ /-\?-/);       # private marker
    $prot{$ssl}->{'WEAK'}++     if ($risk =~ /WEAK/i);
    $prot{$ssl}->{'LOW'}++      if ($risk =~ /LOW/i);
    $prot{$ssl}->{'MEDIUM'}++   if ($risk =~ /MEDIUM/i);
    $prot{$ssl}->{'HIGH'}++     if ($risk =~ /HIGH/i);
    return;
} # checkcipher

sub checkciphers    {
    #? test target if given ciphers are accepted, results stored in global %checks
    # checks are done with information from @cipher_results
    my ($host, $port, @results) = @_;

    _y_CMD("checkciphers() " . $cfg{'done'}->{'checkciphers'});
    $cfg{'done'}->{'checkciphers'}++;
    return if ($cfg{'done'}->{'checkciphers'} > 1);
    _trace("checkciphers($host, $port){");

    if ($#results < 0) {        # no ciphers found; avoid misleading values
        foreach my $key (@{$cfg{'need-cipher'}}) {
            $checks{$key}->{val} = _get_text('miss_cipher', "");
        }
        foreach my $ssl (@{$cfg{'version'}}) { # check all SSL versions
            @{$prot{$ssl}->{'ciphers_pfs'}} = _get_text('miss_cipher', "");
        }
        _trace("checkciphers() }");
        return;
    }

    my $ssl     = "";
    my $cipher  = "";
    my %hasecdsa;   # ECDHE-ECDSA is mandatory for TR-02102-2, see 3.2.3
    my %hasrsa  ;   # ECDHE-RSA   is mandatory for TR-02102-2, see 3.2.3
    foreach my $c (@results) {  # check all accepted ciphers
        next if not @{$c};      # defensive programming ..
        next if ((scalar(@{$c})) =~ m/^\s*$/);  # -"-
        # each $c looks like:  TLSv12  ECDHE-RSA-AES128-GCM-SHA256  yes
        my $yn  = ${$c}[2];
        $cipher = ${$c}[1];
        $ssl    = ${$c}[0];
        if ($yn =~ m/yes/i) {   # cipher accepted
            $prot{$ssl}->{'cnt'}++;
            checkcipher($ssl, $cipher);
            $checks{'logjam'}->{val}   .= _prot_cipher($ssl, $c) if ("" ne _islogjam($ssl, $c));
        }
        $hasrsa{$ssl}  = 1 if ($cipher =~ /$cfg{'regex'}->{'EC-RSA'}/);
        $hasecdsa{$ssl}= 1 if ($cipher =~ /$cfg{'regex'}->{'EC-DSA'}/);
    }

    # additional BEAST check: checks for vulnerable protocols are disabled?
    my $beastskipped = _isbeastskipped($host, $port);
    $checks{'beast'}->{val} .= " " . ${beastskipped} if "" ne $beastskipped;

    $checks{'breach'}->{val} = "<<NOT YET IMPLEMENTED>>";

    foreach my $ssl (@{$cfg{'version'}}) { # check all SSL versions
        $hasrsa{$ssl}  = 0 if not defined $hasrsa{$ssl};    # keep Perl silent
        $hasecdsa{$ssl}= 0 if not defined $hasecdsa{$ssl};  #  -"-
        # TR-02102-2, see 3.2.3
        if ($prot{$ssl}->{'cnt'} > 0) { # checks do not make sense if there're no ciphers
            $checks{'tr_02102+'}->{val} .= _prot_cipher($ssl, $text{'miss_RSA'})   if ($hasrsa{$ssl}   != 1);
            $checks{'tr_02102+'}->{val} .= _prot_cipher($ssl, $text{'miss_ECDSA'}) if ($hasecdsa{$ssl} != 1);
            $checks{'tr_03116+'}->{val} .= $checks{'tr_02102+'}->{val}; # same as TR-02102
            $checks{'tr_03116-'}->{val} .= $checks{'tr_02102-'}->{val}; # -"-
        }
        $checks{'cnt_ciphers'}  ->{val} += $prot{$ssl}->{'cnt'};    # need this with cnt_ prefix
    }
    $checks{'cipher_edh'}->{val} = "" if ($checks{'cipher_edh'}->{val} ne "");  # good if we have them

    # we need our well known string, hence 'sslversion'; SEE Note:Selected Protocol
    $ssl    = $data{'sslversion'}->{val}($host, $port);     # get selected protocol
    $cipher = $data{'cipher_selected'}->{val}($host, $port);# get selected cipher
    if ((defined $prot{$ssl}->{'cnt'}) and (defined $prot{$ssl}->{'ciphers_pfs'})) {
        $checks{'cipher_pfsall'}->{val} = " " if ($prot{$ssl}->{'cnt'} > $#{$prot{$ssl}->{'ciphers_pfs'}});
    } else {
        $checks{'cipher_pfsall'}->{val} = $text{'na'};
    }
    #$checks{'cipher_pfs'}->{val} # done in checkdest()
    _trace("checkciphers() }");
    return;
} # checkciphers

sub checkbleed($$)  {
    #? check if target supports vulnerable TLS extension 15 (hearbeat)
    # SEE Note:heartbleed
    my ($host, $port) = @_;
    _y_CMD("checkbleed() ". $cfg{'done'}->{'checkbleed'});
    $cfg{'done'}->{'checkbleed'}++;
    return if ($cfg{'done'}->{'checkbleed'} > 1);
    my $bleed = _isbleed($host, $port);
    if ($cfg{'ignorenoreply'} > 0) {
        return if ($bleed =~ m/no reply/);
    }
    $checks{'heartbleed'}->{val}  = $bleed;
    return;
} # checkbleed

sub checkdates($$)  {
    # check validation of certificate's before and after date
    my ($host, $port) = @_;
    _y_CMD("checkdates() " . $cfg{'done'}->{'checkdates'});
    $cfg{'done'}->{'checkdates'}++;
    return if ($cfg{'done'}->{'checkdates'} > 1);

    my $before= $data{'before'}->{val}($host);
    my $after = $data{'after'} ->{val}($host);
    my @since = split(/ +/, $before);
    my @until = split(/ +/, $after);
    if ("$before$after" =~ m/^\s*$/) {
        # if there's no data from the certificate, set undef values and return
        $checks{'dates'}->{val}         = $text{'na'};
        $checks{'expired'}->{val}       = $text{'na'};
        $checks{'sts_expired'}->{val}   = $text{'na'};
        $checks{'valid_years'}->{val}   = 0;
        $checks{'valid_months'}->{val}  = 0;
        $checks{'valid_days'}->{val}    = 0;
        return;
    }

   # Note about calculating dates:
   # Calculation should be done without using additional Perl modules like
   #   Time::Local, Date::Calc, Date::Manip, ...
   # Hence we convert dates given by the certificate's before and after value
   # to the format  YYYYMMDD.  The format given in the certificate  is always
   # GMT and in fixed form: MMM DD hh:mm:ss YYYY GMT. So a split() gives year
   # and day as integer.  Just the month is a string, which must be converted
   # to an integer using the map() funtion on @mon array.
   # The same format is used for the current date given by gmtime(), but
   # convertion is much simpler as no strings exist here.
    my @now = gmtime(time);
    my @mon = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
    my $m   = 0;
    my $s_mon = 0; my $u_mon = 0;
    if (@since) { my $dum = map({$m++; $s_mon=$m if/$since[0]/} @mon); $m = 0; }
    if (@until) { my $dum = map({$m++; $u_mon=$m if/$until[0]/} @mon); $m = 0; }
        # my $dum =   keeps Perl::Critic happy
    my $now   = sprintf("%4d%02d%02d", $now[5]+1900, $now[4]+1, $now[3]);
    my $start = sprintf("%s%02s%02s",  $since[3], $s_mon, $since[1]);
    my $end   = sprintf("%s%02s%02s",  $until[3], $u_mon, $until[1]);
    my $txt   = "";
    # end date magic, do checks ..
    $checks{'dates'}->{val}         =          $before if ($now < $start);
    $checks{'dates'}->{val}        .= " .. " . $after  if ($now > $end);
    $checks{'expired'}->{val}       =          $after  if ($now > $end);
    $data{'valid_years'}->{val}     = ($until[3]       -  $since[3]);
    $data{'valid_months'}->{val}    = ($until[3] * 12) - ($since[3] * 12) + $u_mon - $s_mon;
    $data{'valid_days'}->{val}      = ($data{'valid_years'}->{val}  *  5) + ($data{'valid_months'}->{val} * 30); # approximately
    $data{'valid_days'}->{val}      = ($until[1] - $since[1]) if ($data{'valid_days'}->{val} < 60); # more accurate

    # The current timestamp is added to the  STS max-age  to check if the STS
    # max-age exceeds the certificate's expire date. All timestamps are given
    # in epoch timestamp format.
    # The  after  value from the certificate must be converted to epoch time-
    # stamp format, and then can be compared to STS max-age.
    # Unfortunately there exist  no simple method to convert a human readable
    # timestamps (like certificate's  after) into epoch timestamp format.
    # Perl's  Time::Local module is used for that in the hope that it is part
    # of most Perl installations. Existance of Time::Local module was already
    # done at startup with and +sts_expired disabled if missing.
    # SEE Perl:import include
    MAXAGE_CHECK: {
        $txt = $text{'na_STS'};
        last MAXAGE_CHECK if ($data{'https_sts'}->{val}($host) eq "");
        $txt = STR_UNDEF;
        last MAXAGE_CHECK if (!_is_do('sts_expired'));
        $txt = "";
        # compute epoch timestamp from 'after'
        my $ts = Time::Local::timelocal(reverse(split(/:/, $until[2])), $until[1], $u_mon - 1, $until[3]);
        my $maxage = $data{'hsts_maxage'}->{val}($host);
        $now = time();  # we need epoch timestamp here
        $txt = "$now + $maxage > $ts" if ($now + $maxage > $ts);
    }
    $checks{'sts_expired'} ->{val}  = $txt;

    _trace("checkdates: start, now, end: : $start, $now, $end");
    _trace("checkdates: valid:       " . $checks{'dates'}->{val});
    _trace("checkdates: valid-years: " . $data{'valid_years'}->{val});
    _trace("checkdates: valid-month: " . $data{'valid_months'}->{val} . "  = ($until[3]*12) - ($since[3]*12) + $u_mon - $s_mon");
    _trace("checkdates: valid-days:  " . $data{'valid_days'}->{val}   . "  = (" . $data{'valid_years'}->{val} . "*5) + (" . $data{'valid_months'}->{val} . "*30)");
    return;
} # checkdates

sub checkcert($$)   {
    #? check certificate settings
    my ($host, $port) = @_;
    my ($value, $label);
    _y_CMD("checkcert() " . $cfg{'done'}->{'checkcert'});
    $cfg{'done'}->{'checkcert'}++;
    return if ($cfg{'done'}->{'checkcert'} > 1);

    # wildcards (and some sizes)
    _checkwildcard($host, $port);
    # $checks{'certfqdn'}->{val} ... done in checksni()

    $checks{'rootcert'}->{val}  = $data{'issuer'}->{val}($host) if ($data{'subject'}->{val}($host) eq $data{'issuer'}->{val}($host));
    $checks{'ocsp_uri'}->{val}  = " " if ($data{'ocsp_uri'}->{val}($host) eq "");
    $checks{'cps'}->{val}       = " " if ($data{'ext_cps'}->{val}($host)  eq "");
    $checks{'crl'}->{val}       = " " if ($data{'ext_crl'}->{val}($host)  eq "");

    if ($cfg{'usehttp'} > 0) {
        # at least 'ext_crl' may contain more than one URL
        $checks{'crl_valid'}->{val} = "";
        $value = $data{'ext_crl'}->{val}($host);
        if ($value eq '<<openssl>>') { # TODO: <<openssl>> from Net::SSLinfo
            $checks{'crl_valid'}->{val} = $text{'na_openssl'};
        } else {
            _trace("ext_crl: $value");  # may have something other than http://...
            foreach my $url (split(/\s+/, $value)) {
                next if ($url =~ m/^\s*$/);     # skip empty url
                if ($url !~ m/^\s*http$/) {
                    _trace("ext_uri skipped: $url");
                    next;
                }
                $checks{'crl_valid'}->{val}  .= check_url($url, 'ext_crl') || "";
            }
        }
        $checks{'ocsp_valid'}->{val} = "";
        $value = $data{'ocsp_uri'}->{val}($host);
        if ($value eq '<<openssl>>') {
            $checks{'crl_valid'}->{val} = $text{'na_openssl'};
        } else {
            _trace("ocsp_uri: $value");
            foreach my $url (split(/\s+/, $value)) {
                next if ($url =~ m/^\s*$/);     # skip empty url
                if ($url !~ m/^\s*http$/) {
                    _trace("ocsp_uri skipped: $url");
                    next;
                }
                $checks{'ocsp_valid'}->{val} .= check_url($url, 'ocsp_uri') || "";
            }
        }
    } else {
        $checks{'crl_valid'}->{val} = _get_text('disabled', "--no-http");
        $checks{'ocsp_valid'}->{val}= _get_text('disabled', "--no-http");
    }
    $value = $data{'ext_constraints'}->{val}($host);
    $checks{'constraints'}->{val}   = " "    if ($value eq "");
    $checks{'constraints'}->{val}   = $value if ($value !~ m/CA:FALSE/i);
    # TODO: more checks necessary:
    #    KeyUsage field must set keyCertSign and/or the BasicConstraints field has the CA attribute set TRUE.

    check_certchars($host, $port);

    # certificate
    if ($cfg{'verbose'} > 0) { # TODO
        foreach my $label (qw(verify selfsigned)) {
            #dbx# _dbx "$label : $value #";
            $value = $data{$label}->{val}($host);
            $checks{$label}->{val}   = $value if ($value eq "");

# FIXME:  $data{'verify'} $data{'error_verify'} $data{'error_depth'}
#   if (_is_do('verify')) {
#       print "";
#       print "Hostname validity:       "  . $data{'verify_hostname'}->{val}($host);
#       print "Alternate name validity: "  . $data{'verify_altname'}->{val}( $host);
#   }
#
#   if (_is_do('altname')) {
#       print "";
#       print "Certificate AltNames:    "  . $data{'altname'}->{val}(        $host);
#       print "Alternate name validity: "  . $data{'verify_altname'}->{val}( $host);
#   }
        }
    }
    $value = $data{'selfsigned'}->{val}($host); # may contain:  0 (ok)
    $checks{'selfsigned'}    ->{val} = $value if ($value !~ m/^(?:0\s+.ok.)*$/);
    $checks{'fp_not_md5'}    ->{val} = $data{'fingerprint'} if ('MD5' eq $data{'fingerprint'});
    $value = $data{'signame'}->{val}($host);
    $checks{'sha2signature'} ->{val} = $value if ($value !~ m/^$cfg{'regex'}->{'SHA2'}/);
    $checks{'sig_encryption'}->{val} = $value if ($value !~ m/$cfg{'regex'}->{'encryption'}/i);
    $checks{'sig_enc_known'} ->{val} = $value if ($value !~ m/^$cfg{'regex'}->{'encryption_ok'}|$cfg{'regex'}->{'encryption_no'}$/i); ## no critic qw(RegularExpressions::ProhibitComplexRegexes)
    $value = $data{'pubkey_algorithm'}->{val}($host);
    $checks{'pub_encryption'}->{val} = $value if ($value !~ m/$cfg{'regex'}->{'encryption'}/i);
    $checks{'pub_enc_known'} ->{val} = $value if ($value !~ m/^$cfg{'regex'}->{'encryption_ok'}|$cfg{'regex'}->{'encryption_no'}$/i); ## no critic qw(RegularExpressions::ProhibitComplexRegexes)

# TODO: ocsp_uri pruefen; Soft-Fail, Hard-Fail

# TODO: check: serialNumber: Positive number up to a maximum of 20 octets.
# TODO: check: Signature: Must be the same OID as that defined in SignatureAlgorithm below.
# TODO: check: Version
# TODO: check: validity (aka dates)
# TODO: check: Issuer
#        Only CN=, C=, ST=, O=, OU= and serialNumber= must be supported the rest are optional
# TODO: check: Subject
#        The subject field can be empty in which case the entity being authenticated is defined in the subjectAltName.

    return;
} # checkcert

sub checksni($$)    {
    #? check if given FQDN needs to use SNI
    # sets $checks{'sni'}, $checks{'certfqdn'}
    my ($host, $port) = @_;
    _y_CMD("checksni() "  . $cfg{'done'}->{'checksni'});
    $cfg{'done'}->{'checksni'}++;
    return if ($cfg{'done'}->{'checksni'} > 1);

    if ($cfg{'usesni'} == 1) {      # useless check for --no-sni
        if ($data{'cn_nosni'}->{val} eq $host) {
            $checks{'sni'}->{val}   = "";
        } else {
            $checks{'sni'}->{val}   = $data{'cn_nosni'}->{val};
        }
    }
    # $checks{'certfqdn'} and $checks{'hostname'} are similar
    if ($cfg{'no_cert'} != 0) {
        $checks{'certfqdn'}->{val}  = $cfg{'no_cert_txt'};
        $checks{'hostname'}->{val}  = $cfg{'no_cert_txt'};
        return;
    }
    if ($data{'cn'}->{val}($host) eq $host) {
        $checks{'certfqdn'}->{val}  = "";
        $checks{'hostname'}->{val}  = "";
    } else {
        $checks{'certfqdn'}->{val}  = $data{'cn_nosni'}->{val} . " <> " . $host;
        $checks{'hostname'}->{val}  = $host . " <> " . $data{'cn'}->{val}($host);
    }
    #dbx# _dbx "host:\t\t"           . $host;
    #dbx# _dbx "data{cn}:\t\t"       . $data{'cn'}->{val}($host);
    #dbx# _dbx "data{cn_nosni}:\t"   . $data{'cn_nosni'}->{val};
    #dbx# _dbx "checks{hostname}:\t" . $checks{'hostname'}->{val};
    #dbx# _dbx "checks{certfqdn}:\t" . $checks{'certfqdn'}->{val};
    return;
} # checksni

sub _base2  {
    #? return base-2 of given number
    my $value = shift;
       $value = log($value);
    # base-2 = log($value) / log(2)
    # unfortunatelly this calculation results in  "inf"  for big values
    # to avoid using Math::BigInt for big values, the calculation is done 
    # as follows (approximately):
    #   log(2)   = 0.693147180559945;
    #   1/log(2) = 1.44269504088896;
    #   v * 1.44 = v + (v / 100 * 44);
    return ($value + ($value/100*44)); 
} # _base2

sub checksizes($$)  {
    #? compute some lengths and count from certificate values
    # sets %checks
    my ($host, $port) = @_;
    my $value;
    _y_CMD("checksizes() " . $cfg{'done'}->{'checksizes'});
    $cfg{'done'}->{'checksizes'}++;
    return if ($cfg{'done'}->{'checksizes'} > 1);

    checkcert($host, $port) if ($cfg{'no_cert'} == 0); # in case we missed it before
    $value =  $data{'pem'}->{val}($host);
    $checks{'len_pembase64'}->{val} = length($value);
    $value =~ s/(----.+----\n)//g;
    chomp $value;
    $checks{'len_pembinary'}->{val} = sprintf("%d", length($value) / 8 * 6) + 1; # simple round()
    $checks{'len_subject'}  ->{val} = length($data{'subject'} ->{val}($host));
    $checks{'len_issuer'}   ->{val} = length($data{'issuer'}  ->{val}($host));
    $checks{'len_cps'}      ->{val} = length($data{'ext_cps'} ->{val}($host));
    $checks{'len_crl'}      ->{val} = length($data{'ext_crl'} ->{val}($host));
    #$checks{'len_crl_data'} ->{val} = length($data{'crl'}     ->{val}($host));
    $checks{'len_ocsp'}     ->{val} = length($data{'ocsp_uri'}->{val}($host));
    #$checks{'len_oids'}     ->{val} = length($data{'oids'}->{val}($host));
    $checks{'len_sernumber'}->{val} = int(length($data{'serial_hex'}->{val}($host)) / 2); # value are hex octets
        # Note: RFC5280 limits the serial number to an integer with not more
        #       than 20 octets. It should also be not a negative number.
        # It's assumed that a octet equals one byte.

    if ($cmd{'extopenssl'} == 1) {
        # TODO: find a better way to do this ugly check
        $value = $data{'modulus_len'}->{val}($host);
        $checks{'len_publickey'}->{val} = (($value =~ m/^\s*$/) ? 0 : $value);
        $value = $data{'modulus_exponent'}->{val}($host);  # i.e. 65537 (0x10001) or prime256v1
        if ($value =~ m/prime/i) {  # public key uses EC with primes
            $value =~ s/\n */ /msg;
            $checks{'modulus_exp_1'}     ->{val}    = "<<N/A $value>>";
            $checks{'modulus_exp_65537'} ->{val}    = "<<N/A $value>>";
            $checks{'modulus_exp_oldssl'}->{val}    = "<<N/A $value>>";
            $checks{'modulus_size_oldssl'}->{val}   = "<<N/A $value>>";
        } else  {                   # only traditional exponent needs to be checked
            if ($value eq '<<openssl>>') {  # TODO: <<openssl>> from Net::SSLinfo
                $checks{'modulus_exp_1'}     ->{val}= $text{'na_openssl'};
                $checks{'modulus_exp_65537'} ->{val}= $text{'na_openssl'};
                $checks{'modulus_exp_oldssl'}->{val}= $text{'na_openssl'};
            } else {
                $value =~ s/^(\d+).*/$1/;
                if ($value =~ m/^\d+$/) {   # avoid Perl warning "Argument isn't numeric"
                    $checks{'modulus_exp_1'}     ->{val}= $value if ($value == 1);
                    $checks{'modulus_exp_65537'} ->{val}= $value if ($value != 65537);
                    $checks{'modulus_exp_oldssl'}->{val}= $value if ($value >  65536);
                } else {
                    $checks{'modulus_exp_1'}     ->{val}= $text{'na'};
                    $checks{'modulus_exp_65537'} ->{val}= $text{'na'};
                    $checks{'modulus_exp_oldssl'}->{val}= $text{'na'};
                }
            }
            $value = $data{'modulus'}->{val}($host); # value are hex digits
            if ($value eq '<<openssl>>') {
                $checks{'modulus_size_oldssl'}->{val}   = $text{'na_openssl'};
            } else {
                $checks{'modulus_size_oldssl'}->{val}   = length($value) * 4 if ((length($value) * 4) > 16384);
            }
        }
        $value = $data{'serial_int'}->{val}($host) + 0;
        my $bits_of_value = _base2($value);
        $checks{'sernumber'}    ->{val} = "$bits_of_value  > 160" if ($bits_of_value > 160);
        $value = $data{'sigkey_len'}->{val}($host);
        $checks{'len_sigdump'}  ->{val} = (($value =~ m/^\s*$/) ? 0 : $value); # missing without openssl
    } else { # missing without openssl
        $checks{'sernumber'}    ->{val} = $text{'na_openssl'};
        $checks{'len_sigdump'}  ->{val} = $text{'na_openssl'};
        $checks{'len_publickey'}->{val} = $text{'na_openssl'};
        $checks{'modulus_exp_1'}->{val} = $text{'na_openssl'};
        $checks{'modulus_exp_65537'} ->{val} = $text{'na_openssl'};
        $checks{'modulus_exp_oldssl'}->{val} = $text{'na_openssl'};
        $checks{'modulus_size_oldssl'}->{val}= $text{'na_openssl'};
    }
    return;
} # checksizes

sub check02102($$)  {
    #? check if target is compliant to BSI TR-02102-2 2016-01
    # assumes that checkciphers() and checkdest() already done
    my ($host, $port) = @_;
    _y_CMD("check02102() " . $cfg{'done'}->{'check02102'});
    $cfg{'done'}->{'check02102'}++;
    return if ($cfg{'done'}->{'check02102'} > 1);
    my $txt = "";
    my $val = "";

    # description (see CHECK in o-saft-man.pm) ...
    # lines starting with #! are headlines from TR-02102-2

    # All checks according ciphers already done in checkciphers() and stored
    # in $checks{'tr_02102.'}. We need to do checks according certificate and
    # protocol and fill other %checks values according requirements.

    #! TR-02102-2 3.2 SSL/TLS-Versionen
    # use 'session_protocol' instead of 'sslversion' as its string matches the
    # TR-02102 requirements better; SEE Note:Selected Protocol
    $val  = ($data{'session_protocol'}->{val}($host, $port) !~ m/TLSv1.?2/) ? " <<not TLSv12>>" : "" ;
    $val .= ($prot{'SSLv2'}->{'cnt'}  > 0) ? _get_text('insecure', "protocol SSLv2") : "";
    $val .= ($prot{'SSLv3'}->{'cnt'}  > 0) ? _get_text('insecure', "protocol SSLv3") : "";
    $val .= ($prot{'TLSv1'}->{'cnt'}  > 0) ? _get_text('insecure', "protocol TLSv1") : "";
    $checks{'tr_02102-'}->{val}.= $val;
    $val .= ($prot{'TLSv11'}->{'cnt'} > 0) ? _get_text('insecure', "protocol TLSv11") : "";
    $checks{'tr_02102+'}->{val}.= $val;

    #! TR-02102-2 3.3.1 Empfohlene Cipher Suites
    #! TR-02102-2 3.3.2 Übergangsregelungen
        # cipher checks are already done in checkciphers()

    #! TR-02102-2 3.4.1 Session Renegotation
    $val = ($checks{'renegotiation'}->{val} ne "") ? $text{'no_reneg'} : "";
    $checks{'tr_02102+'}->{val}.= $val;
    $checks{'tr_02102-'}->{val}.= $val;

    #! TR-02102-2 3.4.2 Verkürzung der HMAC-Ausgabe
        # FIXME: cannot be tested because openssl does not suppot it (11/2016)
    $val = ($data{'tlsextensions'}->{val}($host, $port) =~ m/truncated.*hmac/i)
           ? _get_text('enabled_extension', 'truncated HMAC') : "" ;
    $checks{'tr_02102+'}->{val}.= $val;
    $checks{'tr_02102-'}->{val}.= $val;

    #! TR-02102-2 3.4.3 TLS-Kopression und CRIME
    $checks{'tr_02102+'}->{val}.= $checks{'crime'}->{val};
    $checks{'tr_02102-'}->{val}.= $checks{'crime'}->{val};

    #! TR-02102-2 3.4.4 Der Lucky 13-Angriff
    $val = $checks{'lucky13'}->{val};
    $val = ($val ne "") ? _get_text('insecure', "cipher $val; Lucky13") : "" ;
    $checks{'tr_02102+'}->{val}.= $val;
    # check for Lucky 13 in strict mode only (requires GCM)

    #! TR-02102-2 3.4.5 Die "Encrypt-then-MAC"-Erweiterung
        # FIXME: cannot be tested because openssl does not suppot it (11/2016)

    #! TR-02102-2 3.4.6 Die Heartbeat-Erweiterung
    $val = "";
    $val = ($data{'heartbeat'}->{val}($host, $port) ne "")
           ? _get_text('enabled_extension', 'heartbeat') : "";
    $checks{'tr_02102+'}->{val}.= $val;
    $checks{'tr_02102-'}->{val}.= $val;

    #! TR-02102-2 3.4.7 Die Extended Master Secret Extension
        # FIXME: cannot be tested because openssl does not suppot it (11/2016)

    #! TR-02102-2 3.5 Authentisierung der Kommunikationspartner
        # check are not possible from remote

    #! TR-02102-2 3.6 Domainparameter und Schlüssellängen
    $val = $checks{'len_sigdump'}->{val};
    if ($val =~ m/\d+/) {       # avoid Perl warning "Argument isn't numeric"
        $val = ($val < 2000) ? _get_text('bit2048', $val) : "";
        # FIXME: lazy check does not honor used cipher
    } else {
        $val = " len_sigdump missing $val";
    }
    $checks{'tr_02102+'}->{val}.= $val;
    $checks{'tr_02102-'}->{val}.= $val;

    #check_dh($host, $port);    # need DH Parameter
        # FIXME: check see for example check7525()

    #! TR-02102-2 3.6.1 Verwendung von elliptischen Kurven
        # brainpoolP256r1, brainpoolP384r1, brainpoolP512r1 (vgl. [RFC5639] und [RFC7027])
        # lazy allows: secp256r1, secp384r1
        # verboten:    secp224r1
    # TODO: cipher bit length check

    #! TR-02102-2 4.1 Schlüsselspeicherung
    #! TR-02102-2 4.2 Umgang mit Ephemeralschlüsseln
    #! TR-02102-2 4.3 Zufallszahlen
        # these checks are not possible from remote

    return;
} # check02102

sub check2818($$)   {
    #? check if subjectAltNames is RFC 2818 compliant
    my ($host, $port) = @_;
    _y_CMD("check2818() " . $cfg{'done'}->{'check2818'});
    $cfg{'done'}->{'check2818'}++;
    return if ($cfg{'done'}->{'check2818'} > 1);
    my $val = $data{'verify_altname'}->{val}($host);
    $checks{'rfc_2818_names'}->{val} = $val if ($val !~ m/matches/); # see Net::SSLinfo.pm
    return;
} # check2818

sub check03116($$)  {
    #? check if target is compliant to BSI TR-03116-4
    my ($host, $port) = @_;
    # BSI TR-03116-4 is similar to BSI TR-02102-2
    _y_CMD("check03116() " . $cfg{'done'}->{'check03116'});
    $cfg{'done'}->{'check03116'}++;
    return if ($cfg{'done'}->{'check03116'} > 1);
    my $txt = "";

    # All checks according ciphers already done in checkciphers() and stored
    # in $checks{'tr_03116'}. We need to do checks according certificate and
    # protocol and fill other %checks values according requirements.

    #! TR-03116-4 2.1.1 TLS-Versionen und Sessions
        # muss mindestens die TLS-Version 1.2 unterstützt werden

    # use 'session_protocol' instead of 'sslversion' as its string matches the
    # TR-03116 requirements better; SEE Note:Selected Protocol
    $txt  = ($data{'session_protocol'}->{val}($host, $port) !~ m/TLSv1.?2/) ? " <<not TLSv12>>" : "" ;
    $txt .= ($prot{'SSLv2'}->{'cnt'}  > 0) ? _get_text('insecure', "protocol SSLv2") : "";
    $txt .= ($prot{'SSLv3'}->{'cnt'}  > 0) ? _get_text('insecure', "protocol SSLv3") : "";
    $txt .= ($prot{'TLSv1'}->{'cnt'}  > 0) ? _get_text('insecure', "protocol TLSv1") : "";
    $txt .= ($prot{'TLSv11'}->{'cnt'} > 0) ? _get_text('insecure', "protocol TLSv11") : "";
    $checks{'tr_03116-'}->{val}.= $txt;
    $checks{'tr_03116+'}->{val}.= $txt;

    #! TR-03116-4 2.1.2 Cipher Suites
    $checks{'tr_03116+'}->{val}.= $checks{'tr_03116+'}->{val};
    $checks{'tr_03116-'}->{val}.= $checks{'tr_03116-'}->{val};

    #! TR-03116-4 2.1.1 TLS-Versionen und Sessions
        # TLS Session darf eine Lebensdauer von 2 Tagen nicht überschreiten
    #! TR-03116-4 2.1.4.2 Encrypt-then-MAC-Extension
    #! TR-03116-4 2.1.4.3 OCSP-Stapling
    $checks{'tr_03116+'}->{val} .= _get_text('missing', 'OCSP') if ($data{'ocsp_uri'}->{val}($host)  eq "");

    #! TR-03116-4 4.1.1 Zertifizierungsstellen/Vertrauensanker
        # muss für die Verifikation von Zertifikaten einen oder mehrere Vertrauensanker vorhalten
        # Die Zahl der Vertrauensanker sollte so gering wie möglich gehalten werden.
# FIXME:

    #! TR-03116-4 4.1.2 Zertifikate
        # müssen die folgenden Anforderungen erfüllen:
        # * Alle Zertifikate müssen ...
        # ** jederzeit aktuelle CRLs zur Verfügung stehen, oder
        # ** eine AuthorityInfoAccess-Extension mit OCSP
        # * Endnutzerzertifikate dürfen eine Gültigkeitsdauer von höchstens drei,
        #   CA-Zertifikate von höchstens fünf Jahren haben.
        # * CA-Zertifikate müssen eine BasicConstraints-Extension enthalten.
        # * Das in der Extension enthaltene Feld pathLenConstraint muss
        #   vorhanden sein und auf einen möglichst kleinen Wert gesetzt werden.
        # * Alle Zertifikate müssen eine KeyUsage-Extension enthalten.
        # * Zertifikate dürfen keine Wildcards CommonName des Subject oder
        #   SubjectAltName enthalten.
        # Verwendung von Extended-Validation-Zertifikaten wird empfohlen
    $txt = _get_text('cert_valid', $data{'valid_years'}->{val}); # NOTE: 'valid_years' is special value
    $checks{'tr_03116+'}->{val} .= $txt                if ($data{'valid_years'}->{val} > 3);
# FIXME: cert itself and CA-cert have different validity: 3 vs. 5 years
    $txt = $checks{'wildcard'}->{val};
    if (($data{'ext_crl'}->{val}($host) eq "") && ($data{'ext_authority'}->{val}($host) eq "")) {
        $checks{'tr_03116+'}->{val} .= _get_text('missing', 'AIA or CRL');
    }
# FIXME: need to verify provided CRL and OCSP
    $checks{'tr_03116+'}->{val} .= _get_text('wildcards', $txt) if ($txt ne "");
    # _checkwildcard() checks for CN and subjectAltname only, we need Subject also
    $txt = $data{'subject'}->{val}($host);
    $checks{'tr_03116+'}->{val} .= _get_text('wildcards', "Subject:$txt") if ($txt =~ m/[*]/);
# FIXME: need to check wildcards in all certificates

    #! TR-03116-4 4.1.3 Zertifikatsverifikation
        # * vollständige Prüfung der Zertifikatskette bis zu einem für die
        #   jeweilige Anwendung vertrauenswürdigen und als authentisch
        #   bekannten Vertrauensanker
# FIXME:
        # * Prüfung auf Gültigkeit (Ausstellungs- und Ablaufdatum)
        # * Rückrufprüfung aller Zertifikate
    $txt = $checks{'dates'}->{val};
    $checks{'tr_03116+'}->{val} .= _get_text('cert_dates', $txt) if ($txt ne "");
    $txt = $checks{'expired'}->{val};
    $checks{'tr_03116+'}->{val} .= _get_text('cert_valid', $txt) if ($txt ne "");

    #! TR-03116-4 4.1.4 Domainparameter und Schlüssellängen
        # ECDSA 224 Bit; DSA 2048 Bit; RSASSA-PSS 2048 Bit; alle SHA-224
        # empfohlene ECC:
        # * BrainpoolP224r1 3 , BrainpoolP256r1, BrainpoolP384r1, BrainpoolP512r1
        # * NIST Curve P-224, NIST Curve P-256, NIST Curve P-384, NIST Curve P-521
# FIXME:

    #! TR-03116-4 5.2 Zufallszahlen
        # these checks are not possible from remote

    $checks{'tr_03116-'}->{val} .= $checks{'tr_03116+'}->{val};

    return;
} # check03116

sub check6125($$)   {
    #? check if certificate identifiers are RFC 6125 compliant
    my ($host, $port) = @_;
    _y_CMD("check6125() " . $cfg{'done'}->{'check6125'});
    $cfg{'done'}->{'check6125'}++;
    return if ($cfg{'done'}->{'check6125'} > 1);

    my $txt = "";
    my $val = "";

    #from: https://www.rfc-editor.org/rfc/rfc6125.txt
    #   ... only references which are relevant for checks here
    # 6.4.  Matching the DNS Domain Name Portion
    #   (collection of descriptions for following rules)
    # 6.4.1.  Checking of Traditional Domain Names
    #   domain name labels using a case-insensitive ASCII comparison, as
    #   clarified by [DNS-CASE] (e.g., "WWW.Example.Com" would be lower-cased
    #   to "www.example.com" for comparison purposes).  Each label MUST match
    #   in order for the names to be considered to match, except as
    #   supplemented by the rule about checking of wildcard labels
    #   (Section 6.4.3).
    # 6.4.2.  Checking of Internationalized Domain Names
    # 6.4.3.  Checking of Wildcard Certificates
    #   ...
    #   1.  The client SHOULD NOT attempt to match a presented identifier in
    #       which the wildcard character comprises a label other than the
    #       left-most label (e.g., do not match bar.*.example.net).
    #   2.  If the wildcard character is the only character of the left-most
    #       label in the presented identifier, the client SHOULD NOT compare
    #       against anything but the left-most label of the reference
    #       identifier (e.g., *.example.com would match foo.example.com but
    #       not bar.foo.example.com or example.com).
    #   3.  The client MAY match a presented identifier in which the wildcard
    #       character is not the only character of the label (e.g.,
    #       baz*.example.net and *baz.example.net and b*z.example.net would
    #       be taken to match baz1.example.net and foobaz.example.net and
    #       buzz.example.net, respectively).  However, the client SHOULD NOT
    #       attempt to match a presented identifier where the wildcard
    #       character is embedded within an A-label or U-label [IDNA-DEFS] of
    #       an internationalized domain name [IDNA-PROTO].
    # 6.5.2.  URI-ID
    #   The scheme name portion of a URI-ID (e.g., "sip") MUST be matched in
    #   a case-insensitive manner, in accordance with [URI].  Note that the
    #   ":" character is a separator between the scheme name and the rest of
    #   the URI, and thus does not need to be included in any comparison.
    # TODO: nothing
    # 7.2.  Wildcard Certificates
    #   o  There is no specification that defines how the wildcard character
    #      may be embedded within the A-labels or U-labels [IDNA-DEFS] of an
    #      internationalized domain name [IDNA-PROTO]; as a result,
    #      implementations are strongly discouraged from including or
    #      attempting to check for the wildcard character embedded within the
    #      A-labels or U-labels of an internationalized domain name (e.g.,
    #      "xn--kcry6tjko*.example.org").  Note, however, that a presented
    #      domain name identifier MAY contain the wildcard character as long
    #      as that character occupies the entire left-most label position,
    #      where all of the remaining labels are valid NR-LDH labels,
    #      A-labels, or U-labels (e.g., "*.xn--kcry6tjko.example.org").
    # 7.3.  Internationalized Domain Names
    #   Allowing internationalized domain names can lead to the inclusion of
    #   visually similar (so-called "confusable") characters in certificates;
    #   for discussion, see for example [IDNA-DEFS].

    # Note: wildcards itself are checked in   checkcert() _checkwildcard()
    $txt = $data{'cn'}->{val}($host);
    $val     .= " <<6.4.2:cn $txt>>"      if ($txt !~ m!$cfg{'regex'}->{'isDNS'}!);
    $val     .= " <<6.4.3:cn $txt>>"      if ($txt =~ m!$cfg{'regex'}->{'doublewild'}!);
    $val     .= " <<6.4.3:cn $txt>>"      if ($txt =~ m!$cfg{'regex'}->{'invalidwild'}!);
    $val     .= " <<7.2.o:cn $txt>>"      if ($txt =~ m!$cfg{'regex'}->{'invalidIDN'}!);
    $val     .= " <<7.3:cn $txt>>"        if ($txt =~ m!$cfg{'regex'}->{'isIDN'}!);
    $txt = $data{'subject'}->{val}($host);
    $txt =~ s!^.*CN=!!;         # just value of CN=
    $val     .= " <<6.4.2:subject $txt>>" if ($txt !~ m!$cfg{'regex'}->{'isDNS'}!);
    $val     .= " <<6.4.3:subject $txt>>" if ($txt =~ m!$cfg{'regex'}->{'doublewild'}!);
    $val     .= " <<6.4.3:subject $txt>>" if ($txt =~ m!$cfg{'regex'}->{'invalidwild'}!);
    $val     .= " <<7.2.o:subject $txt>>" if ($txt =~ m!$cfg{'regex'}->{'invalidIDN'}!);
    $val     .= " <<7.3:subject $txt>>"   if ($txt =~ m!$cfg{'regex'}->{'isIDN'}!);
    foreach my $txt (split(" ", $data{'altname'}->{val}($host))) {
        $txt  =~ s!.*:!!;        # strip prefix
        $val .= " <<6.4.2:altname $txt>>" if ($txt !~ m!$cfg{'regex'}->{'isDNS'}!);
        $val .= " <<6.4.3:altname $txt>>" if ($txt =~ m!$cfg{'regex'}->{'doublewild'}!);
        $val .= " <<6.4.3:altname $txt>>" if ($txt =~ m!$cfg{'regex'}->{'invalidwild'}!);
        $val .= " <<7.2.o:altname $txt>>" if ($txt =~ m!$cfg{'regex'}->{'invalidIDN'}!);
        $val .= " <<7.3:altname $txt>>"   if ($txt =~ m!$cfg{'regex'}->{'isIDN'}!);
    }
    $checks{'rfc_6125_names'}->{val} = $val;

    return;
} # check6125

sub check7525($$)   {
    #? check if target is RFC 7525 compliant
    my ($host, $port) = @_;
    _y_CMD("check7525() " . $cfg{'done'}->{'check7525'});
    $cfg{'done'}->{'check7525'}++;
    return if ($cfg{'done'}->{'check7525'} > 1);
    my $val = "";

    # All checks according ciphers already done in checkciphers() and stored
    # in $checks{'rfc_7525'}. We need to do checks according certificate and
    # protocol and fill other %checks values according requirements.

    # descriptions from: https://www.rfc-editor.org/rfc/rfc7525.txt

    # 3.1.1.  SSL/TLS Protocol Versions
    #    Implementations MUST support TLS 1.2 [RFC5246] and MUST prefer to
    #    negotiate TLS version 1.2 over earlier versions of TLS.
    #    Implementations SHOULD NOT negotiate TLS version 1.1 [RFC4346];
    #    the only exception is when no higher version is available in the
    #    negotiation.
    # TODO: for lazy check

    # use 'session_protocol' instead of 'sslversion' as its string matches the
    # RFC requirements better; SEE Note:Selected Protocol
    $val  = " <<not TLSv12>>" if ($data{'session_protocol'}->{val}($host, $port) !~ m/TLSv1.?2/);
    $val .= " SSLv2"   if ( $prot{'SSLv2'}->{'cnt'}   > 0);
    $val .= " SSLv3"   if ( $prot{'SSLv3'}->{'cnt'}   > 0);
    $val .= " TLSv1"   if (($prot{'TLSv11'}->{'cnt'} + $prot{'TLSv12'}->{'cnt'}) > 0);
    $val .= " TLSv11"  if (($prot{'TLSv11'}->{'cnt'}  > 0) and ($prot{'TLSv12'}->{'cnt'} > 0));

    # 3.1.2.  DTLS Protocol Versions
    #    Implementations SHOULD NOT negotiate DTLS version 1.0 [RFC4347].
    #    Implementations MUST support and MUST prefer to negotiate DTLS
    #    version 1.2 [RFC6347].

    $val .= " DTLSv1"  if ( $prot{'DTLSv1'}->{'cnt'}  > 0);
    $val .= " DTLSv11" if ( $prot{'DTLSv11'}->{'cnt'} > 0);
    # TODO: we currently (5/2015) do not support DTLSv1x

    # 3.1.3.  Fallback to Lower Versions
    # no checks, as already covered by 3.1.1 checks

    # 3.2.  Strict TLS
    #    ... TLS-protected traffic (such as STARTTLS),
    #    clients and servers SHOULD prefer strict TLS configuration.
    #
    #    HTTP client and server implementations MUST support the HTTP
    #    Strict Transport Security (HSTS) header [RFC6797]

    # FIXME: what to check for STARTTLS?

    $val .= " DTLSv11" if ( $prot{'DTLSv11'}->{'cnt'} > 0);
    checkhttp($host, $port);    # need http_sts
    $val .= _get_text('missing', 'STS') if ($checks{'hsts_sts'} eq "");
    # TODO: strict TLS checks are for STARTTLS only, not necessary here

    # 3.3.  Compression
    #    ... implementations and deployments SHOULD
    #    disable TLS-level compression (Section 6.2.2 of [RFC5246]), unless
    #    the application protocol in question has been shown not to be open to
    #    such attacks.

    if ($data{'compression'}->{val}($host) =~ /$cfg{'regex'}->{'nocompression'}/) {
        $val .= $data{'compression'}->{val}($host);
    }

    # 3.4.  TLS Session Resumption
    #    ... the resumption information MUST be authenticated and encrypted ..
    #    A strong cipher suite MUST be used when encrypting the ticket (as
    #    least as strong as the main TLS cipher suite).
    #    Ticket keys MUST be changed regularly, e.g., once every week, ...
    #    For similar reasons, session ticket validity SHOULD be limited to
    #    a reasonable duration (e.g., half as long as ticket key validity).

    if ($data{'resumption'}->{val}($host) eq "") {
        $val .= _get_text('insecure', 'resumption');
        $val .= _get_text('missing',  'session ticket') if ($data{'session_ticket'}->{val}($host) eq "");
        $val .= _get_text('insecure', 'randomness of session') if ($checks{'session_random'}->{val} ne "");
    }
    # TODO: session ticket must be random
    # FIXME: session ticket must be authenticated and encrypted

    # 3.5.  TLS Renegotiation
    #    ... both clients and servers MUST implement the renegotiation_info
    #    extension, as defined in [RFC5746].

    $val .= _get_text('missing',  'renegotiation_info extension') if ($data{'tlsextensions'}->{val}($host, $port) !~ m/renegotiation info/);
    $val .= _get_text('insecure', 'renegotiation') if ($data{'renegotiation'}->{val}($host)  eq "");

    # 3.6.  Server Name Indication
    #    TLS implementations MUST support the Server Name Indication (SNI)

    checksni($host, $port);    # need sni
    $val .= "<<SNI not supported>>" if ($checks{'sni'}->{val} eq "");
    # TODO: need a reliable check if SNI is supported

    # 4.  Recommendations: Cipher Suites
    # 4.1.  General Guidelines
    #    Implementations MUST NOT negotiate the cipher suites with NULL encryption.
    #    Implementations MUST NOT negotiate RC4 cipher suites.
    #    Implementations MUST NOT negotiate cipher suites offering less
    #    than 112 bits of security, ...
    #    Implementations SHOULD NOT negotiate cipher suites that use
    #    algorithms offering less than 128 bits of security.
    # TODO: for lazy check
    #    Implementations SHOULD NOT negotiate cipher suites based on RSA
    #    key transport, a.k.a. "static RSA".
    #    Implementations MUST support and prefer to negotiate cipher suites
    #    offering forward secrecy, ...
    #
    # 4.2.  Recommended Cipher Suites
    #    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    #    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384

    #  ==> done in checkcipher() with _isrfc7525

    # 4.3.  Public Key Length
    #    ... DH key lengths of at least 2048 bits are RECOMMENDED.
    #    ... Curves of less than 192 bits SHOULD NOT be used.

    check_dh($host, $port);    # need DH Parameter
    if ($data{'dh_parameter'}->{val}($host) =~ m/ECDH/) {
        $val .= _get_text('insecure', "DH Parameter: $checks{'ecdh_256'}->{val}") if ($checks{'ecdh_256'}->{val} ne "");
    } else {
        $val .= _get_text('insecure', "DH Parameter: $checks{'dh_2048'}->{val}")  if ($checks{'dh_2048'}->{val}  ne "");
        # TODO: $check...{val} may already contain "<<...>>"; remove it
    }
    # TODO: use get_dh_paramter() for more reliable check

    # 4.5.  Truncated HMAC
    #    Implementations MUST NOT use the Truncated HMAC extension, defined in
    #    Section 7 of [RFC6066].

    $val .= _get_text('missing', 'truncated HMAC extension') if ($data{'tlsextensions'}->{val}($host, $port) =~ m/truncated.*hmac/i);
    #$val .= _get_text('missing', 'session ticket extension') if ($data{'tlsextensions'}->{val}($host, $port) !~ m/session.*ticket/);
    #$val .= _get_text('missing', 'session ticket lifetime extension') if ($data{'session_lifetime'}->{val}($host, $port) eq "");

    # 6.  Security Considerations
    # 6.1.  Host Name Validation
    #    If the host name is discovered indirectly and in an insecure manner
    #    (e.g., by an insecure DNS query for an MX or SRV record), it SHOULD
    #    NOT be used as a reference identifier [RFC6125] even when it matches
    #    the presented certificate.  This proviso does not apply if the host
    #    name is discovered securely (for further discussion, see [DANE-SRV]
    #    and [DANE-SMTP]).

    $val .=  $text{'EV_subject_host'} if ($checks{'hostname'}->{val} ne "");

    # 6.2.  AES-GCM
    # FIXME: implement

    # 6.3.  Forward Secrecy
    #    ... therefore advocates strict use of forward-secrecy-only ciphers.
    # FIXME: implement

    # 6.4.  Diffie-Hellman Exponent Reuse
    # FIXME: implement

    # 6.5.  Certificate Revocation
    #    ... servers SHOULD support the following as a best practice
    #    OCSP [RFC6960]
    #    The OCSP stapling extension defined in [RFC6961]

    $val .= _get_text('missing', 'OCSP') if ($checks{'ocsp_uri'}->{val}  ne "");
    $val .= $checks{'ocsp_valid'}->{val};
    $val .= _get_text('missing', 'CRL in certificate') if ($checks{'crl'}->{val} ne "");
    $val .= $checks{'crl_valid'}->{val};

    # All checks for ciphers were done in _isrfc7525() and already stored in
    # $checks{'rfc_7525'}. Because it may be a huge list, it is appended.
    $checks{'rfc_7525'}->{val} = $val . " " . $checks{'rfc_7525'}->{val};

    return;
} # check7525

sub checkdv($$)     {
    #? check if certificate is DV-SSL
    my ($host, $port) = @_;
    _y_CMD("checkdv() "   . $cfg{'done'}->{'checkdv'});
    $cfg{'done'}->{'checkdv'}++;
    return if ($cfg{'done'}->{'checkdv'} > 1);

    # DV certificates must have:
    #    CN= value in either the subject or subjectAltName
    #    C=, ST=, L=, OU= or O= should be either blank or contain appropriate
    #        text such as "not valid".  # TODO: match $cfg{'regex'}->{'EV-empty'}
    # TODO: reference missing

    my $cn      = $data{'cn'}->{val}($host);
    my $subject = $data{'subject'}->{val}($host);
    my $altname = $data{'altname'}->{val}($host); # space-separated values
    my $oid     = '2.5.4.3';                      # /CN= or commonName
    my $txt     = "";

       # following checks work like:
       #   for each check add descriptive failture text (from %text)
       #   to $checks{'dv'}->{val} if check fails

    check_certchars($host, $port);      # should already be done in checkcert()

    # required CN=
    if ($cn =~ m/^\s*$/) {
        $checks{'dv'}->{val} .= _get_text('missing', "Common Name");
        return; # .. as all other checks will fail too now
    }

    # CN= in subject or subjectAltname,  $1 is matched FQDN
    if (($subject !~ m#/$cfg{'regex'}->{$oid}=(?:[^/\n]*)#)
    and ($altname !~ m#/$cfg{'regex'}->{$oid}=(?:[^\s\n]*)#)) {
        $checks{'dv'}->{val} .= _get_text('missing', $data_oid{$oid}->{txt});
        return; # .. as ..
    }
    ($txt = $subject) =~ s#/.*?$cfg{'regex'}->{$oid}=##;
    $txt = "" if not defined $txt;  # defensive programming ..

# TODO: %data_oid not yet used
    $data_oid{$oid}->{val} = $txt if ($txt !~ m/^\s*$/);
    $data_oid{$oid}->{val} = $cn  if ($cn  !~ m/^\s*$/);

    # there's no rule that CN's value must match the hostname, somehow ..
    # we check at least if subject or subjectAltname match hostname
    if ($txt ne $cn) {  # mismatch
        $checks{'dv'}->{val} .= $text{'EV_subject_CN'};
    }
    if ($txt ne $host) {# mismatch
        if (0 >= (grep{/^DNS:$host$/} split(/[\s]/, $altname))) {
            $checks{'dv'}->{val} .= $text{'EV_subject_host'};
        }
    }

    return;
} # checkdv

sub checkev($$)     {
    #? check if certificate is EV-SSL
    my ($host, $port) = @_;
    _y_CMD("checkev() "   . $cfg{'done'}->{'checkev'});
    $cfg{'done'}->{'checkev'}++;
    return if ($cfg{'done'}->{'checkev'} > 1);

    # most information must be provided in `subject' field
    # unfortunately the specification is a bit vague which X509  keywords
    # must be used, hence we use RegEx to math the keyword assigned value
    #
    # { According EV Certificate Guidelines - Version 1.0 https://www.cabforum.org/contents.html
    # == Required ==
    # Organization name:   subject:organizationName (OID 2.5.4.10 )
    # Business Category:   subject:businessCategory (OID 2.5.4.15)
    # Domain name:         subject:commonName (OID 2.5.4.3) or SubjectAlternativeName:dNSName
    #     This field MUST contain one of the following strings in UTF-8
    #     English: 'V1.0, Clause 5.(b)', 'V1.0, Clause 5.(c)' or 'V1.0, Clause 5.(d)',
    #     depending whether the Subject qualifies under the terms of Section 5b, 5c, or
    #     5d of the Guidelines, respectively.
    # Jurisdiction of Incorporation or Registration:
    #     Locality:        subject:jurisdictionOfIncorporationLocalityName (OID 1.3.6.1.4.1.311.60.2.1.1)
    #     State or Province:subject:jurisdictionOfIncorporationStateOrProvinceName (OID 1.3.6.1.4.1.311.60.2.1.2)
    #     Country:         subject:jurisdictionOfIncorporationCountryName (OID 1.3.6.1.4.1.311.60.2.1.3)
    # Registration Number: subject:serialNumber (OID 2.5.4.5)
    # Physical Address of Place of Business
    #     City or town:    subject:localityName (OID 2.5.4.7)
    #     State or province: subject:stateOrProvinceName (OID 2.5.4.8)
    #     Number & street: subject:streetAddress (OID 2.5.4.9)
    #
    # Maximum Validity Period  27 months (recommended: EV Subscriber certificate 12 months)
    #
    # == Optional ==
    # Physical Address of Place of Business
    #     Country:         subject:countryName (OID 2.5.4.6)
    #     Postal code:     subject:postalCode (OID 2.5.4.17)
    # Compliance with European Union Qualified Certificates Standard In addition,
    # CAs MAY include a qcStatements extension per RFC 3739. The OID for
    #                      qcStatements:qcStatement:statementId is 1.3.6.1.4.1.311.60.2.1
    #
    # }
    # Issuer Domain Component: issuer:domainComponent (OID 0.9.2342.19200300.100.1.25)
    #
    # See also: http://www.evsslcertificate.com

    my $oid     = "";
    my $subject = $data{'subject'}->{val}($host);
    my $cn      = $data{'cn'}->{val}($host);
    my $alt     = $data{'altname'}->{val}($host);
    my $txt     = "";
    my $key     = "";

       # following checks work like:
       #   for each check add descriptive failture text (from %text)
       #   to $checks{'ev+'}->{val} if check fails

    check_certchars($host, $port);      # should already be done in checkcert()
    checkdv($host, $port);
    $checks{'ev+'}->{val} = $checks{'dv'}->{val}; # wrong for DV then wrong for EV too

    # required OID
    foreach my $oid (qw(
        1.3.6.1.4.1.311.60.2.1.1   1.3.6.1.4.1.311.60.2.1.3
        2.5.4.5    2.5.4.7   2.5.4.10   2.5.4.15
        )) {
        if ($subject =~ m#/$cfg{'regex'}->{$oid}=([^/\n]*)#) {
            $data_oid{$oid}->{val} = $1;
            _v2print("EV: " . $cfg{'regex'}->{$oid} . " = $1");
        } else {
            _v2print("EV: " . _get_text('missing', $cfg{'regex'}->{$oid}) . "; required");
            $txt = _get_text('missing', $data_oid{$oid}->{txt});
            $checks{'ev+'}->{val} .= $txt;
            $checks{'ev-'}->{val} .= $txt;
        }
    }
    $oid = '1.3.6.1.4.1.311.60.2.1.2'; # or /ST=
    if ($subject !~ m#/$cfg{'regex'}->{$oid}=(?:[^/\n]*)#) {
        $txt = _get_text('missing', $data_oid{$oid}->{txt});
        $checks{'ev+'}->{val} .= $txt;
        $oid = '2.5.4.8'; # or /ST=
        if ($subject =~ m#/$cfg{'regex'}->{'2.5.4.8'}=([^/\n]*)#) {
            $data_oid{$oid}->{val} = $1;
        } else {
            $checks{'ev-'}->{val} .= $txt;
            _v2print("EV: " . _get_text('missing', $cfg{'regex'}->{$oid}) . "; required");
        }
    }
    $oid = '2.5.4.9'; # may be missing
    if ($subject !~ m#/$cfg{'regex'}->{$oid}=(?:[^/\n]*)#) {
        $txt = _get_text('missing', $data_oid{$oid}->{txt});
        $checks{'ev+'}->{val} .= $txt;
        _v2print("EV: " . $cfg{'regex'}->{$oid} . " = missing+");
        _v2print("EV: " . _get_text('missing', $cfg{'regex'}->{$oid}) . "; required");
    }
    # optional OID
    foreach my $oid (qw(2.5.4.6 2.5.4.17)) {
    }
    if (64 < length($data_oid{'2.5.4.10'}->{val})) {
        $txt = _get_text('EV_large', "64 < " . $data_oid{$oid}->{txt});
        $checks{'ev+'}->{val} .= $txt;
        _v2print("EV: " . $txt);
    }
    # validity <27 months
    if ($data{'valid_months'}->{val} > 27) {
        $txt = _get_text('cert_valid', "27 < " . $data{'valid_months'}->{val});
        $checks{'ev+'}->{val} .= $txt;
        _v2print("EV: " . $txt);
    }

    # TODO: wildcard no, SAN yes
    # TODO: cipher 2048 bit?
    # TODO: potential dangerous OID: '1.3.6.1.4.1.311.60.1.1'
    # TODO: Scoring: 100 EV+SGC; 80 EV; 70 EV-; 50 OV; 30 DV
    return;
} # checkev

sub checkroot($$)   {
    #? check if certificate is root CA
    my ($host, $port) = @_;
    $cfg{'done'}->{'checkroot'}++;
    return if ($cfg{'done'}->{'checkroot'} > 1);

    # SEE Note:root-CA

    return;
} # checkroot

sub checkprot($$)   {
    #? check anything related to SSL protocol versions
    my ($host, $port) = @_;
    my $ssl;
    _y_CMD("checkprot() " . $cfg{'done'}->{'checkprot'});
    $cfg{'done'}->{'checkprot'}++;
    return if ($cfg{'done'}->{'checkprot'} > 1);

    # check SSL version support
    # NOTE: the check is adapted to the text in $%check_dest{'hassslv2'}->{txt}
    $checks{'hassslv2'}->{val}      = " " if ($prot{'SSLv2'}->{'cnt'}  >  0);
    $checks{'hassslv3'}->{val}      = " " if ($prot{'SSLv3'}->{'cnt'}  >  0);
    $checks{'hastls10'}->{val}      = " " if ($prot{'TLSv1'}->{'cnt'}  <= 0);
    $checks{'hastls11'}->{val}      = " " if ($prot{'TLSv11'}->{'cnt'} <= 0);
    $checks{'hastls12'}->{val}      = " " if ($prot{'TLSv12'}->{'cnt'} <= 0);
    $checks{'hastls13'}->{val}      = " " if ($prot{'TLSv13'}->{'cnt'} <= 0);
    # SSLv2 and SSLv3 are special
        # If $cfg{$ssl}=0, the check may be disabled, i.e. with --no-sslv3 .
        # If the protocol  is supported by the target,  at least  one cipher
        # must be accpted. So the amount of ciphers must be > 0.
    if ($cfg{'SSLv2'} == 0) {
        $checks{'hassslv2'}->{val}  = _get_text('disabled', "--no-SSLv2");
        $checks{'drown'}->{val}     = _get_text('disabled', "--no-SSLv2");
    } else {
        if ($prot{'SSLv2'}->{'cnt'} > 0) {
            $checks{'hassslv2'}->{val}  = " " if ($cfg{'nullssl2'} == 1);   # SSLv2 enabled, but no ciphers
            $checks{'drown'}->{val}     = " ";  # SSLv2 there, then potentially vulnerable to DROWN
        }
    }
    if ($cfg{'SSLv3'} == 0) {
        $checks{'hassslv3'}->{val}  = _get_text('disabled', "--no-SSLv3");
        $checks{'poodle'}  ->{val}  = _get_text('disabled', "--no-SSLv3");
    } else {    # SSLv3 enabled, check if there are ciphers
        if ($prot{'SSLv3'}->{'cnt'} > 0) {
            $checks{'hassslv3'}->{val}  = " ";  # POODLE if SSLv3 and ciphers
            $checks{'poodle'}  ->{val}  = "SSLv3";
        }
    }

    # check ALPN and NPN support
    checkalpn($host, $port);    #
    my ($key, $value);
    $key    = 'alpns';
    $value  = $data{$key}->{val}($host, $port);
    $checks{'hasalpn'}->{val}   = " " if ($value eq "");
    #$checks{'hasalpn'}->{val}   = _get_text('disabled', "--no-alpn") if ($cfg{'usealpn'} < 1);
    $key    = 'npns';
    $value  = $data{$key}->{val}($host, $port);
    $checks{'hasnpn'}->{val}    = " " if ($value eq "");
    #$checks{'hasnpn'}->{val}    = _get_text('disabled', "--no-npn")  if ($cfg{'usenpn'}  < 1);
    return;
} # checkprot


sub checkdest($$)   {
    #? check anything related to target and connection
    my ($host, $port) = @_;
    my $ciphers = shift;
    my ($key, $value, $ssl, $cipher);
    _y_CMD("checkdest() " . $cfg{'done'}->{'checkdest'});
    $cfg{'done'}->{'checkdest'}++;
    return if ($cfg{'done'}->{'checkdest'} > 1);

    checksni($host, $port);     # set checks according hostname
    # $cfg{'IP'} and $cfg{'rhost'} already contain $text{'disabled'}
    # if --proxyhost was used; hence no need to check for proxyhost again
    $checks{'reversehost'}->{val}   = $host . " <> " . $cfg{'rhost'} if ($cfg{'rhost'} ne $host);
    $checks{'reversehost'}->{val}   = $text{'na_dns'}   if ($cfg{'usedns'} <= 0);
    $checks{'ip'}->{val}            = $cfg{'IP'};

    # SEE Note:Selected Protocol
    # get selected cipher and store in %checks, also check for PFS
    $cipher = $data{'cipher_selected'} ->{val}($host, $port);
    $ssl    = $data{'session_protocol'}->{val}($host, $port);
    $ssl    =~ s/[ ._-]//g;     # convert TLS1.1, TLS 1.1, TLS-1_1, etc. to TLS11
    my @prot = grep{/(^$ssl$)/i} @{$cfg{'versions'}};
    if ($#prot == 0) {          # found exactly one matching protocol
        $checks{'cipher_pfs'}->{val}= $cipher if ("" ne _ispfs($ssl, $cipher));
    } else {
        _warn("631: protocol '". join(';', @prot) . "' does not match; no selected protocol available");
    }

    # PFS is scary if the TLS session ticket is not random
    #  we should have different tickets in %data0 and %data
    #  it's ok if both are empty 'cause then no tickets are used
    $key   = 'session_ticket';
    $value = $data{$key}->{val}($host, $port);
    if (defined $data0{$key}->{val}) {  # avoid Perl warning "Use uninitialized value in string"
        $checks{'session_random'}->{val} = $value if ($value eq $data0{$key}->{val});
    } else {
        $checks{'session_random'}->{val} = $text{'na'};
    }

    checkprot($host, $port);

    # vulnerabilities
    check_dh($host,$port); # Logjam vulnerability
    $checks{'crime'}->{val} = _iscrime($data{'compression'}->{val}($host), $data{'next_protocols'}->{val}($host));
    foreach my $key (qw(resumption renegotiation)) {
        $value = $data{$key}->{val}($host);
        $checks{$key}->{val} = " " if ($value eq "");
    }
    #     Secure Renegotiation IS NOT supported
    $value = $data{'renegotiation'}->{val}($host);
    $checks{'renegotiation'}->{val} = $value if ($value =~ m/ IS NOT /i);
    $value = $data{'resumption'}->{val}($host);
    $checks{'resumption'}->{val}    = $value if ($value !~ m/^Reused/);

    # check target specials
    foreach my $key (qw(krb5 psk_hint psk_identity srp session_ticket session_lifetime)) { # master_key session_id: see %check_dest above also
        $value = $data{$key}->{val}($host);
        $checks{$key}->{val} = " "    if ($value eq "");
        $checks{$key}->{val} = "None" if ($value =~ m/^\s*None\s*$/i);
        # if supported we have a value
        # TODO: see ZLIB also (seems to be wrong currently)
    }
    foreach my $key (qw(heartbeat)) { # these are good if there is no value
        $checks{$key}->{val} = $data{$key}->{val}($host);
        $checks{$key}->{val} = ""     if ($checks{$key}->{val} =~ m/^\s*$/);
    }
    $checks{'heartbeat'}->{val} = $text{'na_tlsextdebug'} if ($cfg{'use_extdebug'} < 1);
    return;
} # checkdest

sub checkhttp($$)   {
    #? HTTP(S) checks
    my ($host, $port) = @_;
    my $key = "";
    _y_CMD("checkhttp() " . $cfg{'done'}->{'checkhttp'});
    $cfg{'done'}->{'checkhttp'}++;
    return if ($cfg{'done'}->{'checkhttp'} > 1);

    # collect informations
    my $notxt = " "; # use a variable to make assignments below more human readable
    my $http_sts      = $data{'http_sts'}     ->{val}($host) || ""; # value may be undefined, avoid Perl error
    my $http_location = $data{'http_location'}->{val}($host) || ""; #  "
    my $hsts_maxage   = $data{'hsts_maxage'}  ->{val}($host);       # 0 is valid here, hence || does not work
       $hsts_maxage   = -1 if ($data{'hsts_maxage'}->{val}($host) =~ m/^\s*$/);
    my $hsts_fqdn     = $http_location;
       $hsts_fqdn     =~ s|^(?:https:)?//([^/]*)|$1|i; # get FQDN even without https:
       $hsts_fqdn     =~ s|/.*$||;                     # remove trailing path

    $checks{'hsts_is301'}->{val} = $data{'http_status'}->{val}($host) if ($data{'http_status'}->{val}($host) !~ /301/); # RFC6797 requirement
    $checks{'hsts_is30x'}->{val} = $data{'http_status'}->{val}($host) if ($data{'http_status'}->{val}($host) =~ /30[0235678]/); # not 301 or 304
    # perform checks
    # sequence important: first check if redirect to https, then check if empty
    $checks{'http_https'}->{val} = $http_location if ($http_location !~ m/^\s*https:/);
    $checks{'http_https'}->{val} = $notxt if ($http_location =~ m/^\s*$/);
    $checks{'hsts_redirect'}->{val} = $data{'https_sts'}->{val}($host) if ($http_sts ne "");
    if ($data{'https_sts'}->{val}($host) ne "") {
        my $fqdn =  $hsts_fqdn;
        $checks{'hsts_location'}->{val} = $data{'https_location'}->{val}($host) if ($data{'https_location'}->{val}($host) ne "");
        $checks{'hsts_refresh'} ->{val} = $data{'https_refresh'} ->{val}($host) if ($data{'https_refresh'} ->{val}($host) ne "");
        $checks{'hsts_ip'}      ->{val} = $host        if ($host =~ m/\d+\.\d+\.\d+\.\d+/); # RFC6797 requirement
        $checks{'hsts_fqdn'}    ->{val} = $hsts_fqdn   if ($http_location !~ m|^https://$host|i);
        $checks{'hsts_samehost'}->{val} = $hsts_fqdn   if ($fqdn ne $host);
        $checks{'hsts_sts'}     ->{val} = $notxt       if ($data{'https_sts'}   ->{val}($host) eq "");
        $checks{'sts_subdom'}   ->{val} = $notxt       if ($data{'hsts_subdom'} ->{val}($host) eq "");
        $checks{'sts_preload'}  ->{val} = $notxt       if ($data{'hsts_preload'}->{val}($host) eq "");
        $checks{'sts_maxage'}   ->{val} = $hsts_maxage if (($hsts_maxage > $checks{'sts_maxage1m'}->{val}) or ($hsts_maxage < 1));
        $checks{'sts_maxage'}   ->{val}.= " = " . int($hsts_maxage / $checks{'sts_maxage1d'}->{val}) . " days" if ($checks{'sts_maxage'}->{val} ne ""); # pretty print
        $checks{'sts_maxagexy'} ->{val} = ($hsts_maxage > $checks{'sts_maxagexy'}->{val}) ? "" : "< ".$checks{'sts_maxagexy'}->{val};
        $checks{'sts_maxage18'} ->{val} = ($hsts_maxage > $checks{'sts_maxage18'}->{val}) ? "" : "< ".$checks{'sts_maxage18'}->{val};
        $checks{'sts_maxage0d'} ->{val} = ($hsts_maxage == 0) ? "0" : "";
        my $hsts_equiv = $data{'hsts_httpequiv'}->{val}($host);
        $checks{'hsts_httpequiv'}->{val} = $hsts_equiv if ($hsts_equiv ne ""); # RFC6797 requirement
        # other sts_maxage* are done below as they change {val}
        checkdates($host,$port);    # computes check{'sts_expired'}
    } else {
        foreach my $key (qw(sts_subdom sts_maxage sts_maxage00 sts_maxagexy sts_maxage18 sts_maxage0d)) {
            $checks{$key}->{val}    = $text{'na_STS'};
        }
        foreach my $key (qw(hsts_location hsts_refresh hsts_fqdn hsts_samehost hsts_sts)) {
            $checks{$key}->{val}    = $text{'na_STS'};
        }
    }
# TODO: invalid certs are not allowed for HSTS
    $checks{'hsts_fqdn'}->{val} = $text{'na'} if ($http_location eq "");  # useless if no redirect
    $checks{'pkp_pins'} ->{val} = $notxt if ($data{'https_pins'}->{val}($host) eq "");
# TODO: pins= ==> fingerprint des Zertifikats

    $notxt = $text{'na_STS'};
    $notxt = $text{'na_http'} if ($cfg{'usehttp'} < 1);
    # NOTE: following sequence is important!
    foreach my $key (qw(sts_maxage1y sts_maxage1m sts_maxage1d)) {
        if ($data{'https_sts'}->{val}($host) ne "") {
            $checks{'sts_maxage'}->{score} = $checks{$key}->{score} if ($hsts_maxage < $checks{$key}->{val});
            $checks{$key}->{val}    = ($hsts_maxage < $checks{$key}->{val}) ? "" : "> ".$checks{$key}->{val};
        } else {
            $checks{$key}->{val}    = $notxt;
            $checks{$key}->{score}  = 0;
        }
    }
    return;
} # checkhttp

sub checkssl($$)    {
    #? SSL checks
    my ($host, $port) = @_;
    my $ciphers = shift;
    _y_CMD("checkssl() "  . $cfg{'done'}->{'checkssl'});
    $cfg{'done'}->{'checkssl'}++;
    return if ($cfg{'done'}->{'checkssl'} > 1);

    $cfg{'no_cert_txt'} = $text{'na_cert'} if ($cfg{'no_cert_txt'} eq ""); # avoid "yes" results
    if ($cfg{'no_cert'} == 0) {
        # all checks based on certificate can't be done if there was no cert, obviously
        checkcert( $host, $port);   # SNI, wildcards and certificate
        checkdates($host, $port);   # check certificate dates (since, until, exired)
        checkdv(   $host, $port);   # check for DV
        checkev(   $host, $port);   # check for EV
        check02102($host, $port);   # check for BSI TR-02102-2
        check03116($host, $port);   # check for BSI TR-03116-4
        check7525( $host, $port);   # check for RFC 7525
        check6125( $host, $port);   # check for RFC 6125 (identifiers only)
        check2818( $host, $port);   # check for RFC 2818 (subjectAltName only)
        checksni(  $host, $port);   # check for SNI
        checksizes($host, $port);   # some sizes
    } else {
        $cfg{'done'}->{'checksni'}++;  # avoid checking again
        $cfg{'done'}->{'checkdates'}++;# "
        $cfg{'done'}->{'checksizes'}++;# "
        $cfg{'done'}->{'check02102'}++;# "
        $cfg{'done'}->{'check03116'}++;# "
        $cfg{'done'}->{'check7525'}++; # "
        $cfg{'done'}->{'check6125'}++; # "
        $cfg{'done'}->{'check2818'}++; # "
        $cfg{'done'}->{'checkdv'}++;   # "
        $cfg{'done'}->{'checkev'}++;   # "
        foreach my $key (sort keys %checks) { # anything related to certs need special setting
            $checks{$key}->{val} = $cfg{'no_cert_txt'} if (_is_member($key, \@{$cfg{'check_cert'}}));
        }
        $checks{'hostname'} ->{val} = $cfg{'no_cert_txt'};
        $checks{'tr_02102+'}->{val} = $cfg{'no_cert_txt'};
        $checks{'tr_02102-'}->{val} = $cfg{'no_cert_txt'};
        $checks{'tr_03116+'}->{val} = $cfg{'no_cert_txt'};
        $checks{'tr_03116-'}->{val} = $cfg{'no_cert_txt'};
        $checks{'rfc_6125_names'}->{val} = $cfg{'no_cert_txt'};
        $checks{'rfc_2818_names'}->{val} = $cfg{'no_cert_txt'};
    }

    if ($cfg{'usehttp'} == 1) {
        checkhttp( $host, $port);
    } else {
        $cfg{'done'}->{'checkhttp'}++;
        foreach my $key (sort keys %checks) {
            $checks{$key}->{val} = $text{'na_http'} if (_is_member($key, \@{$cfg{'cmd-http'}}));
        }
    }
    # some checks accoring ciphers and compliance are done in checkciphers()
    # and check02102(); some more are done in checkhttp()
    # now do remaining for %checks
    checkdest( $host, $port);

# TODO: folgende Checks implementieren
    foreach my $key (qw(verify_hostname verify_altname verify dates fingerprint)) {
# TODO: nicht sinnvoll wenn $cfg{'no_cert'} > 0
    }

    return;
} # checkssl

sub check_exitcode  {
    #? compute exitcode; returns number of failed checks or insecure settings
    # SEE Note:--exitcode
    my $exitcode   = 0; # total count
    my $cnt_prot   = 0; # number of insecure protocol versions
                        # only TLSv12 is considered secure
    my $cnt_ciph   = 0; # number of insecure ciphers per protocol
    my $cnt_ciphs  = 0; # number of insecure ciphers
    my $cnt_pfs    = 0; # number ciphers without PFS per protocol
    my $cnt_nopfs  = 0; # number ciphers without PFS
    $exitcode = $checks{'cnt_checks_no'}->{val} if ($cfg{'exitcode_checks'} > 0);
# TODO: $cfg{'exitcode_sizes'}
    _v_print("---------------------------------------------------- exitcode {");
    _v_print(sprintf("%s\t%3s %3s %3s %3s %3s %s", qw(protocol H M L W no-PFS insecure)));
    _v_print("-------------+---+---+---+---+------+------------");
    foreach my $ssl (@{$cfg{'versions'}}) { # SEE Note:%prot
        next if ($cfg{$ssl} == 0);  # not requested, don't count
# TODO: counts protocol even if no cipher was supported, is this insecure?
        $cnt_prot++ if ($cfg{$ssl} > 0);
        $cnt_pfs   = $prot{$ssl}->{'cnt'} - $#{$prot{$ssl}->{'ciphers_pfs'}};
        $exitcode += $cnt_pfs                if ($cfg{'exitcode_pfs'}    > 0);
        $cnt_ciph  = 0;
        $cnt_ciph += $prot{$ssl}->{'MEDIUM'} if ($cfg{'exitcode_medium'} > 0);
        $cnt_ciph += $prot{$ssl}->{'WEAK'}   if ($cfg{'exitcode_weak'}   > 0);
        $cnt_ciph += $prot{$ssl}->{'LOW'}    if ($cfg{'exitcode_low'}    > 0);
        $exitcode += $cnt_ciph;
        _v_print(sprintf("%-7s\t%3s %3s %3s %3s %3s\t%s", $ssl,
                $prot{$ssl}->{'HIGH'}, $prot{$ssl}->{'MEDIUM'},
                $prot{$ssl}->{'LOW'},  $prot{$ssl}->{'WEAK'},
                $cnt_pfs, $cnt_ciph,
        ));
        $cnt_ciphs += $cnt_ciph;
        $cnt_nopfs += $cnt_pfs;
    }
    _v_print("-------------+---+---+---+---+------+------------");
    $cnt_prot-- if ($cfg{'TLSv12'} > 0);
    $exitcode += $cnt_prot if ($cfg{'exitcode_prot'} > 0);
    $checks{'cnt_exitcode'}->{val} = $exitcode;
    _v_print(sprintf("%s\t%s", "Total number of insecure protocols",  $cnt_prot));
    _v_print(sprintf("%s\t%s", "Total number of insecure ciphers",    $cnt_ciphs));
    _v_print(sprintf("%s\t%s", "Total number of ciphers without PFS", $cnt_nopfs));
    _v_print(sprintf("%s\t%s", $checks{'cnt_checks_no'}->{txt}, $checks{'cnt_checks_no'}->{val}));
    _v_print(sprintf("%s\t%s", $checks{'cnt_exitcode'}->{txt},  $checks{'cnt_exitcode'}->{val}));
    _v_print("---------------------------------------------------- exitcode }");
    return $checks{'cnt_exitcode'}->{val};
} # check_exitcode

sub scoring         {
    #? compute scoring of all checks; sets values in %scores
    my ($host, $port) = @_;
    my $value;

    # http
    #  some scores are set in checkhttp()
    my $http_location = $data{'http_location'}->{val}($host) || "";
    $scores{'check_http'}->{val}    = 100;
    $checks{'hsts_fqdn'}->{score}   = 0 if ($http_location eq "");

    foreach my $key (sort keys %checks) {
        next if ($key =~ m/^(ip|reversehost)/); # not scored
        next if ($key =~ m/^(sts_)/);           # needs special handlicg
        next if ($key =~ m/^(closure|fallback|cps|krb5|lzo|open_pgp|order|pkp_pins|psk_|rootcert|srp|zlib)/); ## no critic qw(RegularExpressions::ProhibitComplexRegexes)
          # FIXME: not yet scored
        next if ($key =~ m/^TLSv1[123]/); # FIXME:
        $value = $checks{$key}->{val};
        # TODO: go through @cipher_results
# TODO   foreach my $sec (qw(LOW WEAK MEDIUM HIGH -?-)) {
# TODO       # keys in %prot look like 'SSLv2->LOW', 'TLSv11->HIGH', etc.
# TODO       $key = $ssl . '-' . $sec;
# TODO       if ($checks{$key}->{val} != 0) {    # if set, decrement score
# TODO           $scores{'check_ciph'}->{val} -= _getscore($key, 'egal', \%checks);
# TODO printf "%20s: %4s %s\n", $key, $scores{'check_ciph'}->{val}, _getscore($key, 'egal', \%checks);
# TODO       }
# TODO   }
        $scores{'check_size'}->{val} -= _getscore($key, $value, \%checks) if ($checks{$key}->{typ} eq "sizes");
#       $scores{'check_ciph'}->{val} -= _getscore($key, $value, \%checks) if ($checks{$key}->{typ} eq "cipher");
        $scores{'check_http'}->{val} -= _getscore($key, $value, \%checks) if ($checks{$key}->{typ} eq "https"); # done above
        $scores{'check_cert'}->{val} -= _getscore($key, $value, \%checks) if ($checks{$key}->{typ} eq "certificate");
        $scores{'check_conn'}->{val} -= _getscore($key, $value, \%checks) if ($checks{$key}->{typ} eq "connection");
        $scores{'check_dest'}->{val} -= _getscore($key, $value, \%checks) if ($checks{$key}->{typ} eq "destination");
#_dbx "$key " . $checks{$key}->{val} if($checks{$key}->{typ} eq "connection");
#_dbx "score certificate $key : ".$checks{$key}->{val}." - ". $checks{$key}->{score}." = ".$scores{'check_cert'}->{val} if($checks{$key}->{typ} eq "certificate");
#_dbx "score connection  $key : ".$checks{$key}->{val}." - ". $checks{$key}->{score}." = ".$scores{'check_conn'}->{val} if($checks{$key}->{typ} eq "connection");
#_dbx "score destination $key : ".$checks{$key}->{val}." - ". $checks{$key}->{score}." = ".$scores{'check_dest'}->{val} if($checks{$key}->{typ} eq "destination");
#_dbx "score http/https  $key : ".$checks{$key}->{val}." - ". $checks{$key}->{score}." = ".$scores{'check_http'}->{val} if($checks{$key}->{typ} eq "https");
    }
    return;
} # scoring

#| definitions: print functions
#| -------------------------------------

sub _cleanup_data   {
    # cleanup some values (strings) in data
    my ($key, $value) = @_;
    if ($key eq "https_status") {
        # remove non-printables from HTTP Status line
        # such bytes may occour if SSL connection failed
        #_v_print("# removing non-printable characters from $data{$key}->{txt}:");
        _v_print("removing non-printable characters from $key: $value");
        $value =~ s/[^[:print:]]+//g;   # FIXME: not yet perfect
    }
    if ($key =~ m/X509$/) {
        $value =~ s#/([^=]*)#\n   ($1)#g;
        $value =~ s#=#\t#g;
    }
    return $value;
} # _cleanup_data

sub _printdump($$)  {
    my ($label, $value) = @_;
        $label =~ s/\n//g;
        $label = sprintf("%s %s", $label, '_' x (75 -length($label)));
    $value = "" if not defined $value;  # value parameter is optional
    printf("#{ %s\n\t%s\n#}\n", $label, $value);
    # using curly brackets 'cause they most likely are not part of any data
    return;
} # _printdump
sub printdump($$$)  {
    #? just dumps internal database %data and %check_*
    my ($legacy, $host, $port) = @_;   # NOT IMPLEMENTED
    print '######################################################################### %data';
    foreach my $key (keys %data) {
        next if (_is_intern($key) > 0);  # ignore aliases
        _printdump($data{$key}->{txt}, $data{$key}->{val}($host));
    }
    print '######################################################################## %check';
    foreach my $key (keys %checks) { _printdump($checks{$key}->{txt}, $checks{$key}->{val}); }
    return;
} # printdump

sub printruler()    { print "=" . '-'x38, "+" . '-'x35 if ($cfg{'out_header'} > 0); return; }

sub printheader($$) {
    #? print title line and table haeder line if second argument given
    my ($txt, $desc, $rest) = @_;
    return if ($cfg{'out_header'} <= 0);
    print $txt;
    return if ($desc =~ m/^ *$/); # title only if no more arguments
    printf("= %-37s %s\n", $text{'desc'}, $desc);
    printruler();
    return;
} # printheader

sub printfooter($)  {
    #? print footer line according given legacy format
    my $legacy  = shift;
    if ($legacy eq 'sslyze')    { print "\n\n SCAN COMPLETED IN ...\n"; }
    # all others are empty, no need to do anything
    return;
} # printfooter

sub printtitle($$$$) {
    #? print title according given legacy format
    my ($legacy, $ssl, $host, $port) = @_;
    local    $\ = "\n";
    if ($legacy eq 'sslyze')    {
        my $txt = " SCAN RESULTS FOR " . $host . " - " . $cfg{'IP'};
        print "$txt";
        print " " . "-" x length($txt);
    }
    my $txt     = _get_text('out_ciphers', $ssl);
    if ($legacy eq 'sslaudit')  {} # no title
    if ($legacy eq 'sslcipher') { print "Testing $host ..."; }
    if ($legacy eq 'ssldiagnos'){
        print
            "----------------TEST INFO---------------------------\n",
            "[*] Target IP: $cfg{'IP'}\n",
            "[*] Target Hostname: $host\n",
            "[*] Target port: $port\n",
            "----------------------------------------------------\n";
    }
    if ($legacy eq 'sslscan')   { $host =~ s/;/ on port /; print "Testing SSL server $host\n"; }
    if ($legacy eq 'ssltest')   { print "Checking for Supported $ssl Ciphers on $host..."; }
    if ($legacy eq 'ssltest-g') { print "Checking for Supported $ssl Ciphers on $host..."; }
    if ($legacy eq 'testsslserver') { print "Supported cipher suites (ORDER IS NOT SIGNIFICANT):\n  " . $ssl; }
    if ($legacy eq 'thcsslcheck'){print "\n[*] now testing $ssl\n" . "-" x 76; }
    if ($legacy eq 'compact')   { print "=== Checking $ssl Ciphers ..."; }
    if ($legacy eq 'quick')     { printheader($txt, ""); }
    if ($legacy eq 'simple')    { printheader($txt, ""); }
    if ($legacy eq 'full')      { printheader($txt, ""); }
    return;
} # printtitle

sub print_line($$$$$$)  {
    #? print label and value separated by separator
    #? print hostname and key depending on --showhost and --trace-key option
    my ($legacy, $host, $port, $key, $text, $value) = @_;
        $text   = STR_NOTXT if not defined $text;   # defensive programming ..
        $value  = STR_UNDEF if not defined $value;  # .. missing variable declaration
    # general format of a line is:
    #       host:port:#[key]:label: \tvalue
    # legacy=_cipher is special: does not print label and value
    my  $label  = "";
        $label  = sprintf("%s:%s%s", $host, $port, $text{'separator'}) if ($cfg{'showhost'} > 0);
    if ($legacy eq '_cipher') {
        printf("%s#[%s]%s", $label, $key, $text{'separator'}) if ($cfg{'traceKEY'} > 0);
        return;
    }
        $label .= sprintf("#[%-18s", $key . ']'  . $text{'separator'}) if ($cfg{'traceKEY'} > 0);
    if ($legacy =~ m/(compact|full|quick)/) {
        $label .= sprintf("%s",    $text . $text{'separator'});
    } else {
        $label .= sprintf("[%s]",  $key)   if ($legacy eq 'key');
        $label .= sprintf("%-36s", $text . $text{'separator'}) if ($legacy ne 'key');
    }
    # formats full, quick and compact differ in separator
    my $sep = "\t";
       $sep = "\n\t" if ($legacy eq 'full');
       $sep = ""     if ($legacy =~ m/(compact|quick)/);
    printf("%s%s%s\n", $label, $sep, $value);
    return;
} # print_line

sub print_data($$$$)    {
    # print given label and text from %data according given legacy format
    my ($legacy, $host, $port, $key) = @_;
    if (_is_hashkey($key, \%data) < 1) {    # silently ignore unknown labels
        _warn("801: unknown label '$key'; output ignored"); # seems to be a programming error
        return;
    }
    my $label = ($data{$key}->{txt} || ""); # defensive programming ..
    my $value =  $data{$key}->{val}($host, $port) || "";
       $value = _cleanup_data($key, $value);
    if ($key =~ m/X509$/) {                 # always pretty print
        $key =~ s/X509$//;
        # $value done in _cleanup_data()
        print_line($legacy, $host, $port, $key, $data{$key}->{txt}, $value);
        return;
    }
    if ((1 == _is_hexdata($key)) && ($value !~ m/^\s*$/)) {
        # check for empty $value to avoid warnings with -w
        # pubkey_value may look like:
        #   Subject Public Key Info:Public Key Algorithm: rsaEncryptionPublic-Key: (2048 bit)Modulus=00c11b:...
        # where we want to convert the key value only but not its prefix
        # hence the final : is converted to =
        # (seems to happen on Windows only; reason yet unknown)
        $value =~ s/([Mm]odulus):/$1=/; #
        my ($k, $v) = split(/=/, $value);
        if (defined $v) {       # i.e SHA Fingerprint=
            $k .= "=";
        } else {
            $v  = $k;
            $k  = "";
        }
        if ($cfg{'format'} eq "hex") {
            $v =~ s#(..)#$1:#g;
            $v =~ s#:$##;
        }
        if ($cfg{'format'} eq "esc") {
            $v =~ s#(..)#\\x$1#g;
        }
        if ($cfg{'format'} eq "0x") {
            $v =~ s#(..)#0x$1 #g;
            $v =~ s# $##;
        }
        $value = $k . $v;
    }
    $value = "\n" . $value if (_is_member($key, \@{$cfg{'cmd-NL'}}) > 0); # multiline data
    if ($legacy eq 'compact') {
        $value =~ s#:\n\s+#:#g; # join lines ending with :
        $value =~ s#\n\s+# #g;  # squeeze leading white spaces
        $value =~ s#[\n\r]#; #g;# join all lines
        $label =~ s#[\n]##g;
    }
    if ($legacy eq 'full') {    # do some pretty printing
        if ($label =~ m/(^altname)/) { $value =~ s#^ ##;       $value =~ s# #\n\t#g; }
        if ($label =~ m/(subject)/)  { $value =~ s#/#\n\t#g;   $value =~ s#^\n\t##m; }
        if ($label =~ m/(issuer)/)   { $value =~ s#/#\n\t#g;   $value =~ s#^\n\t##m; }
        if ($label =~ m/(serial|modulus|sigkey_value)/) {
                                       $value =~ s#(..)#$1:#g; $value =~ s#:$##; }
        if ($label =~ m/((?:pubkey|sigkey)_algorithm|signame)/) {
            $value =~ s#(with)# $1 #ig;
            $value =~ s#(encryption)# $1 #ig;
        }
    }
    print_line($legacy, $host, $port, $key, $label, $value);
    printhint($key) if ($cfg{'out_hint_info'} > 0);
    return;
} # print_data

sub print_check($$$$$)  {
    #? print label and result of check
    my ($legacy, $host, $port, $key, $value) = @_;
    $value = $checks{$key}->{val} if not defined $value; # defensive programming ..
    my $label = "";
    $label = $checks{$key}->{txt} if ($legacy ne 'key');
    print_line($legacy, $host, $port, $key, $label, $value);
    printhint($key) if ($cfg{'out_hint_check'} > 0);
    return;
} # print_check

sub print_size($$$$)    {
    #? print label and result for length, count, size, ...
    my ($legacy, $host, $port, $key) = @_;
    my $value = "";
    $value = " bytes" if ($key =~ /^(len)/);
    $value = " bits"  if ($key =~ /^len_(modulus|publickey|sigdump)/);
    print_check($legacy, $host, $port, $key, $checks{$key}->{val} . $value);
    return;
} # print_size

sub print_cipherruler_dh{ print "=   " . "-"x35 . "+-------------------------" if ($cfg{'out_header'} > 0); return; }
sub print_cipherruler   { print "=   " . "-"x35 . "+-------+-------" if ($cfg{'out_header'} > 0); return; }
    #? print header ruler line
sub print_cipherhead($) {
    #? print header line according given legacy format
    my $legacy  = shift;
    return if ($cfg{'out_header'} <= 0);
    if ($legacy eq 'sslscan')   { print "\n  Supported Server Cipher(s):"; }
    if ($legacy eq 'ssltest')   { printf("   %s, %s (%s)\n",  'Cipher', 'Enc, bits, Auth, MAC, Keyx', 'supported'); }
    if ($legacy eq 'ssltest-g') { printf("%s;%s;%s;%s\n", 'compliant', 'host:port', 'protocol', 'cipher', 'description'); }
    if ($legacy eq 'simple')    { printf("=   %-34s%s\t%s\n", $text{'cipher'}, $text{'support'}, $text{'security'});
                                  print_cipherruler(); }
    if ($legacy eq 'cipher_dh') { printf("=   %-34s\t%s\n", $text{'cipher'}, $text{'dh_param'});
                                  print_cipherruler_dh(); }
    if ($legacy eq 'full')      {
        # host:port protocol    supported   cipher    compliant security    description
        printf("= %s\t%s\t%s\t%s\t%s\t%s\t%s\n", 'host:port', 'Prot.', 'supp.', $text{'cipher'}, 'compliant', $text{'security'}, $text{'desc'});
    }
    # all others are empty, no need to do anything
    return;
} # print_cipherhead

sub print_cipherline($$$$$$) {
    #? print cipher check result according given legacy format
    my ($legacy, $ssl, $host, $port, $cipher, $support) = @_;
    # variables for better (human) readability
    my $bit   = get_cipher_bits($cipher);
    my $sec   = get_cipher_sec($cipher);
#   my $ssl   = get_cipher_ssl($cipher);
    my $desc  =  join(" ", get_cipher_desc($cipher));
    my $yesno = $text{'legacy'}->{$legacy}->{$support};
    # first our own formats
    my $value = "";
    if ($legacy eq 'full') {
        # host:port protocol    supported   cipher    compliant security    description
        $desc =  join("\t", get_cipher_desc($cipher));
        $desc =~ s/\s*:\s*$//;
    }
    if ($legacy =~ m/compact|full|quick|simple|key/) {
        my $k = sprintf("%s", get_cipher_hex($cipher));
        print_line('_cipher', $host, $port, $k, $cipher, ""); # just host:port:#[key]:
        printf("[%s]\t%-28s\t%s\t%s\n", $k, $cipher, $yesno, $sec) if ($legacy eq 'key');
        printf("    %-28s\t(%s)\t%s\n",     $cipher, $bit,   $sec) if ($legacy eq 'quick');
        printf("    %-28s\t%s\t%s\n",       $cipher, $yesno, $sec) if ($legacy eq 'simple');
        printf("%s %s %s\n",                $cipher, $yesno, $sec) if ($legacy eq 'compact');
        printf("%s\t%s\t%s\t%s\t%s\t%s\n", $ssl, $yesno, $cipher, '-?-', $sec, $desc) if ($legacy eq 'full');
        return;
    }
    # now legacy formats  # TODO: should be moved to postprocessor
    if ($legacy eq 'sslyze')    {
        if ($support eq 'yes')  {
            $support = sprintf("%4s bits", $bit) if ($support eq 'yes');
        } else {
            $support = $yesno;
        }
        printf("\t%-24s\t%s\n", $cipher, $support);
    }
    if ($legacy eq 'sslaudit')  {
        # SSLv2 - DES-CBC-SHA - unsuccessfull
        # SSLv3 - DES-CBC3-SHA - successfull - 80
        printf("%s - %s - %s\n", $ssl, $cipher, $yesno);
    }
    if ($legacy eq 'sslcipher') {
        #   TLSv1:EDH-RSA-DES-CBC3-SHA - ENABLED - STRONG 168 bits
        #   SSLv3:DHE-RSA-AES128-SHA - DISABLED - STRONG 128 bits
        $sec = 'INTERMEDIATE:' if ($sec =~ /LOW/i);
        $sec = 'STRONG'        if ($sec =~ /high/i);
        $sec = 'WEAK'          if ($sec =~ /weak/i);
        printf("   %s:%s - %s - %s %s bits\n", $ssl, $cipher, $yesno, $sec, $bit);
    }
    if ($legacy eq 'ssldiagnos') {
        # [+] Testing WEAK: SSL 2, DES-CBC3-MD5 (168 bits) ... FAILED
        # [+] Testing STRONG: SSL 3, AES256-SHA (256 bits) ... CONNECT_OK CERT_OK
        $sec = ($sec =~ /high/i) ? 'STRONG' : 'WEAK';
        printf("[+] Testing %s: %s, %s (%s bits) ... %s\n", $sec, $ssl, $cipher, $bit, $yesno);
    }
    if ($legacy eq 'sslscan')   {
        #    Rejected  SSLv3  256 bits  ADH-AES256-SHA
        #    Accepted  SSLv3  128 bits  AES128-SHA
        $bit = sprintf("%3s bits", $bit);
        printf("    %s  %s  %s\n", $ssl, $bit, $cipher);
    }
    if ($legacy eq 'ssltest')   {
        # cipher, description, (supported)
        my @arr = @{$ciphers{$cipher}};
        pop(@arr);  # remove last value: tags
        pop(@arr);  # remove last value: score
        shift @arr; # remove 1'st value: security
        shift @arr; # remove 2'nd value: ssl
        $arr[1] .= ' bits';
        $arr[2] .= ' MAC';
        $arr[3] .= ' Auth';
        $arr[4] .= ' Kx';
        my $tmp = $arr[2]; $arr[2] = $arr[3]; $arr[3] = $tmp;
        printf("   %s, %s (%s)\n",  $cipher, join (", ", @arr), $yesno);
    }
    if ($legacy eq 'thcsslcheck') {
        # AES256-SHA - 256 Bits -   supported
        printf("%30s - %3s Bits - %11s\n", $cipher, $bit, $yesno);
    }
        # compliant;host:port;protocol;cipher;description
    if ($legacy eq 'ssltest-g') { printf("%s;%s;%s;%s\n", 'C', $host . ":" . $port, $sec, $cipher, $desc); } # 'C' needs to be checked first
    if ($legacy eq 'testsslserver') { printf("    %s\n", $cipher); }
    return;
} # print_cipherline

sub print_cipherprefered($$$$) {
    #? print prefered cipher according given legacy format
    my ($legacy, $ssl, $host, $port) = @_;
    my $yesno   = 'yes';
    if ($legacy eq 'sslyze')    { print "\n\n      Preferred Cipher Suites:"; }
    if ($legacy eq 'sslaudit')  {} # TODO: cipher name should be DEFAULT
    if ($legacy eq 'sslscan')   { print "\n  Preferred Server Cipher(s):"; $yesno = "";}
    # all others are empty, no need to do anything
    print_cipherline($legacy, $ssl, $host, $port, $data{'cipher_selected'}->{val}($host), $yesno);
    return;
} # print_cipherprefered

sub print_ciphertotals($$$$) {
    #? print total number of ciphers supported for SSL version according given legacy format
    my ($legacy, $ssl, $host, $port) = @_;
    if ($legacy eq 'ssldiagnos') {
        print "\n-= SUMMARY =-\n";
        printf("Weak:         %s\n", $prot{$ssl}->{'WEAK'});
        printf("Intermediate: %s\n", $prot{$ssl}->{'MEDIUM'}); # MEDIUM
        printf("Strong:       %s\n", $prot{$ssl}->{'HIGH'});   # HIGH
    }
    if ($legacy =~ /(full|compact|simple|quick)/) {
        printheader(_get_text('out_summary', $ssl), "");
        _trace_cmd('%checks');
        foreach my $key (qw(LOW WEAK MEDIUM HIGH -?-)) {
            print_line($legacy, $host, $port, "$ssl-$key", $prot_txt{$key}, $prot{$ssl}->{$key});
            # NOTE: "$ssl-$key" does not exist in %checks or %prot
        }
    }
    return;
} # print_ciphertotals

sub _is_print       {
    #? return 1 if parameter indicate printing
    my $enabled = shift;
    my $print_disabled = shift;
    my $print_enabled  = shift;
    return 1 if ($print_disabled == $print_enabled);
    return 1 if ($print_disabled && ($enabled eq 'no' ));
    return 1 if ($print_enabled  && ($enabled eq 'yes'));
    return 0;
} # _is_print

#  NOTE: Perl::Critic's violation for next 2 subs are false positives
sub _print_results($$$$$@)      { ## no critic qw(Subroutines::RequireArgUnpacking)
    #? print all ciphers from @results if match $ssl and $yesno; returns number of checked ciphers for $ssl
    my $legacy  = shift;
    my $ssl     = shift;
    my $host    = shift;
    my $port    = shift;
    my $yesno   = shift; # only print these results, all if empty
    my @results = @_;
    my $print   = 0; # default: do not print
    my $total   = 0;
    local    $\ = "\n";
    foreach my $c (@results) {
        next if  (${$c}[0] ne $ssl);
        $total++;
        next if ((${$c}[2] ne $yesno) and ($yesno ne ""));
        $print = _is_print(${$c}[2], $cfg{'disabled'}, $cfg{'enabled'});
        print_cipherline($legacy, $ssl, $host, $port, ${$c}[1], ${$c}[2]) if ($print == 1);
    }
    return $total;
} # _print_results

sub printcipherall              { ## no critic qw(Subroutines::RequireArgUnpacking)
    #? print all cipher check results from Net::SSLhello::checkSSLciphers()
    #? returns number of unique (enabled) ciphers
    # FIXME: $legacy, --enabled and --disabled not fully supported
    my $legacy  = shift;
    my $ssl     = shift;
    my $host    = shift;
    my $port    = shift;
    my $outtitle= shift; # print title line if 0
    my @results = @_;    # contains only accepted ciphers
    my $uniqe   = 0;     # count unique ciphers
    my $last_r  = "";    # avoid duplicates
    local    $\ = "\n";
    print_cipherhead( $legacy) if ($outtitle == 0);
    foreach my $key (@results) {
        next if ($last_r eq $key);
        my $cipher = get_cipher_suitename($key);
        print_cipherline($legacy, $ssl, $host, $port, $cipher, "yes");
        $last_r = $key;
        $uniqe++;
    }
    print_cipherruler() if ($legacy eq 'simple');
    printfooter($legacy);
    return $uniqe;
} # printcipherall

sub printciphercheck($$$$$@)    { ## no critic qw(Subroutines::RequireArgUnpacking)
    #? print all cipher check results according given legacy format
    my $legacy  = shift;
    my $ssl     = shift;
    my $host    = shift;
    my $port    = shift;
    my $count   = shift; # print title line if 0
    my @results = @_;
    my $total   = 0;
    local    $\ = "\n";
    print_cipherhead( $legacy) if ($count == 0);
    print_cipherprefered($legacy, $ssl, $host, $port) if ($legacy eq 'sslaudit');

    if ($legacy ne 'sslyze') {
        $total = _print_results($legacy, $ssl, $host, $port, "", @results);
            # NOTE: $checks{'cnt_totals'}->{val} is the number of all checked
            # ciphers for all protocols,  here only the number of ciphers for
            # the protocol $ssl should be printed
        print_cipherruler() if ($legacy eq 'simple');
        print_check($legacy, $host, $port, 'cnt_totals', $total) if ($cfg{'verbose'} > 0);
    } else {
        print "\n  * $ssl Cipher Suites :";
        print_cipherprefered($legacy, $ssl, $host, $port);
        if (($cfg{'enabled'} == 1) or ($cfg{'disabled'} == $cfg{'enabled'})) {
            print "\n      Accepted Cipher Suites:";
            $total = _print_results($legacy, $ssl, $host, $port, "yes", @results);
        }
        if (($cfg{'disabled'} == 1) or ($cfg{'disabled'} == $cfg{'enabled'})) {
            print "\n      Rejected Cipher Suites:";
            $total = _print_results($legacy, $ssl, $host, $port, "no", @results);
        }
    }
    #print_ciphertotals($legacy, $ssl, $host, $port);  # up to version 15.10.15
    printfooter($legacy);
    return;
} # printciphercheck

sub printciphers_dh($$$) {
    #? print ciphers and DH parameter from target
    # currently DH parameters are available with openssl only
    my ($legacy, $host, $port) = @_;
    my $openssl_version = get_openssl_version($cmd{'openssl'});
    _trace1("printciphers_dh: openssl_version: $openssl_version");
    if ($openssl_version lt "1.0.2") { # yes Perl can do this check  # TODO: move this check to _check_openssl()
        _warn("811: ancient openssl $openssl_version: using '-msg' option to get DH parameters");
        $cfg{'openssl_msg'} = '-msg' if ($cfg{'openssl'}->{'msg'} == 1);
        require Net::SSLhello; # to parse output of '-msg'; ok here, as Perl handles multiple includes proper
            # SEE Note:Stand-alone
    }
    foreach my $ssl (@{$cfg{'version'}}) {
        printtitle($legacy, $ssl, $host, $port);
        print_cipherhead( 'cipher_dh');
        foreach my $c (@{$cfg{'ciphers'}}) {
            #next if ($c !~ /$cfg{'regex'}->{'EC'}/);
            my ($version, $supported, $dh) = _useopenssl($ssl, $host, $port, $c);
            next if ($supported =~ /^\s*$/);
            # TODO: use print_cipherline();
            # TODO: perform check like check_dh()
            printf("    %-28s\t%s\n", $c, $dh);
        }
# TODO: {
# -------
# cipher dhe oder edh, ecdh dann muss server temp key da sein
# sonst kommt kein temp key z.B RSA oder camellia
#
# wenn dh kommen muesste aber fehlt, dann bei openssl -msg probieren
# -------
# rfc4492 wenn im cert ec oder ecdsa steht (extension) dann duerfen nur solche
# akzeptiert werden; wenn nix im cert steht dann durfen nur rsa akzeptiert werden
# siehe rfc4492 Table 3
# -------
# cipherPcurve ...P256
# TODO: }

        print_cipherruler_dh();
    }
    return;
} # printciphers_dh

sub printcipherprefered {
    #? print table with prefered/selected (default) cipher per protocol
    my ($legacy, $host, $port) = @_;
    local $\ = "\n";
    if ($cfg{'out_header'}>0) {
        printf("= prot.\t%-31s%s\n", "prefered cipher (strong first)", "prefered cipher (weak first)");
        printf("=------+------------------------------+-------------------------------\n");
    }
    foreach my $ssl (@{$cfg{'versions'}}) { # SEE Note:%prot
        next if (($cfg{$ssl} == 0) and ($verbose <= 0));  # not requested with verbose only
        next if ($ssl =~ m/^SSLv2/);    # SSLv2 has no server selected cipher
        my $key = $ssl . $text{'separator'};
           $key = sprintf("[0x%x]", $prot{$ssl}->{hex}) if ($legacy eq 'key');
        printf("%-7s\t%-31s\t%s\n", $key,
                $prot{$ssl}->{'cipher_strong'}, $prot{$ssl}->{'cipher_weak'},
        );
    }
    if ($cfg{'out_header'}>0) {
        printf("=------+------------------------------+-------------------------------\n");
    }
    print_data($legacy, $host, $port, 'cipher_selected');  # SEE Note:Selected Cipher
    return;
} # printcipherprefered

sub printprotocols      {
    #? print table with cipher informations per protocol
    # number of found ciphers, various risks ciphers, default and PFS cipher
    # prints information stored in %prot
    my ($legacy, $host, $port) = @_;
    local $\ = "\n";
    if ($cfg{'out_header'}>0) {
        printf("# H=HIGH  M=MEDIUM  L=LOW  W=WEAK  tot=enabled ciphers  PFS=enabled cipher with PFS\n") if ($verbose > 0);
        printf("%s\t%3s %3s %3s %3s %3s %3s %-31s %s\n", "=", qw(H M L W PFS tot prefered-strong-cipher PFS-cipher));
        printf("=------%s%s\n", ('+---' x 6), '+-------------------------------+---------------');
    }
    #   'PROT-LOW'      => {'txt' => "Supported ciphers with security LOW"},
    foreach my $ssl (@{$cfg{'versions'}}) { # SEE Note:%prot
        next if (($cfg{$ssl} == 0) and ($verbose <= 0));   # not requested with verbose only
        next if ($ssl =~ m/^SSLv2/);    # SSLv2 has no server selected cipher
        my $key = $ssl . $text{'separator'};
           $key = sprintf("[0x%x]", $prot{$ssl}->{hex}) if ($legacy eq 'key');
        print_line('_cipher', $host, $port, $ssl, $ssl, ""); # just host:port:#[key]:
        printf("%-7s\t%3s %3s %3s %3s %3s %3s %-31s %s\n", $key,
                $prot{$ssl}->{'HIGH'}, $prot{$ssl}->{'MEDIUM'},
                $prot{$ssl}->{'LOW'},  $prot{$ssl}->{'WEAK'},
                ($#{$prot{$ssl}->{'ciphers_pfs'}} + 1), $prot{$ssl}->{'cnt'},
                $prot{$ssl}->{'cipher_strong'}, $prot{$ssl}->{'cipher_pfs'}
        );
        # not yet printed: $prot{$ssl}->{'cipher_weak'}, $prot{$ssl}->{'default'}
    }
    if ($cfg{'out_header'}>0) {
        printf("=------%s%s\n", ('+---' x 6), '+-------------------------------+---------------');
    }
    return;
} # printprotocols

sub printciphersummary  {
    #? print summary of cipher check (+cipher, +cipherall, +cipherraw)
    my ($legacy, $host, $port, $total) = @_;
    if ($legacy =~ /(full|compact|simple|quick)/) {   # but only our formats
        printheader("\n" . _get_text('out_summary', ""), "");
        print_check(   $legacy, $host, $port, 'cnt_totals', $total) if ($cfg{'verbose'} > 0);
        printprotocols($legacy, $host, $port);
        printruler() if (not _is_do('quick'));  # FIXME: 'quick' needs to be a parameter
    }
    my $key = $data{'cipher_selected'}->{val}($host, $port);
    print_line($legacy, $host, $port, 'cipher_selected',
               $data{'cipher_selected'}->{txt}, "$key " . get_cipher_sec($key));
    # print_data($legacy, $host, $port, 'cipher_selected');
    _hint("consider testing with options '--cipheralpn=, --ciphernpn=,' also") if ($cfg{'verbose'} > 0);
    return;
} # printciphersummary

sub printdata($$$)  {
    #? print information stored in %data
    my ($legacy, $host, $port) = @_;
    local $\ = "\n";
    printheader($text{'out_infos'}, $text{'desc_info'});
    _trace_cmd('%data');
    if (_is_do('cipher_selected')) {    # value is special
        my $key = $data{'cipher_selected'}->{val}($host, $port);
        print_line($legacy, $host, $port, 'cipher_selected', $data{'cipher_selected'}->{txt}, "$key " . get_cipher_sec($key));
    }
    foreach my $key (@{$cfg{'do'}}) {
        next if (_is_member( $key, \@{$cfg{'commands-NOTYET'}})  > 0);
        next if (_is_member( $key, \@{$cfg{'ignore-out'}})       > 0);
        next if (_is_hashkey($key, \%data) < 1);
        next if ($key eq 'cipher_selected');# value is special, done above
        if ($cfg{'experimental'} == 0) {
            next if (_is_member( $key, \@{$cfg{'commands-EXP'}}) > 0);
        }
        # special handling vor +info--v
        if (_is_do('info--v') > 0) {
            next if ($key eq 'info--v');
            next if ($key =~ m/$cfg{'regex'}->{'commands-INT'}/i);
        } else {
            next if (_is_intern( $key) > 0);
        }
        _y_CMD("(%data)   +" . $key);
        if (_is_member( $key, \@{$cfg{'cmd-NL'}}) > 0) {
            # for +info print multine data only if --v given
            # if command given explizitely, i.e. +text, print
            next if ((_is_do('info') > 0) and ($cfg{'verbose'} <= 0));
        }
        if ($cfg{'format'} eq "raw") {      # should be the only place where format=raw counts
            print $data{$key}->{val}($host);
        } else {
            print_data($legacy, $host, $port, $key);
        }
    }
    return;
} # printdata

sub printchecks($$$) {
    #? print results stored in %checks
    my ($legacy, $host, $port) = @_;
    my $value = "";
    local $\ = "\n";
    printheader($text{'out_checks'}, $text{'desc_check'});
    _trace_cmd(' printchecks: %checks');
    _warn("821: can't print certificate sizes without a certificate (--no-cert)") if ($cfg{'no_cert'} > 0);
    foreach my $key (@{$cfg{'do'}}) {
        _trace("printchecks: (%checks) ?" . $key);
        next if (_is_member( $key, \@{$cfg{'commands-NOTYET'}}) > 0);
        next if (_is_member( $key, \@{$cfg{'ignore-out'}})  > 0);
        next if (_is_hashkey($key, \%checks) < 1);
        next if (_is_intern( $key) > 0);    # ignore aliases
        next if ($key =~ m/$cfg{'regex'}->{'SSLprot'}/); # these counters are already printed
        if ($cfg{'experimental'} == 0) {
            next if (_is_member( $key, \@{$cfg{'commands-EXP'}}) > 0);
        }
        $value = _setvalue($checks{$key}->{val});
        _y_CMD("(%checks) +" . $key);
        if ($key =~ /$cfg{'regex'}->{'cmd-sizes'}/) { # sizes are special
            print_size($legacy, $host, $port, $key) if ($cfg{'no_cert'} <= 0);
        } else {
            # increment counter only here, avoids counting the counter itself
            $checks{'cnt_checks_yes'}->{val}++ if ($value eq "yes");
            $checks{'cnt_checks_no'} ->{val}++ if ($value =~ /^no/);
            print_check($legacy, $host, $port, $key, $value);
        }
    }
    return;
} # printchecks

#| definitions: print functions for help and information
#| -------------------------------------

sub printquit       {
    #? print internal data
    # call this function with:
    #    $0 `\
    #      gawk '/--(help|trace-sub)/{next}/--h$/{next}/\+traceSUB/{next}($2~/^-/){$1="";print}' o-saft-man.pm\
    #      |tr ' ' '\012' \
    #      |sort -u \
    #      |egrep '^(--|\+)' \
    #      |egrep -v '^--[v-]-' \
    #      |egrep -v '--user-*' \
    #      |egrep -v 'cipher=*' \
    #     ` \
    #     +quit --trace-key
    #
    # NOTE: This extracts all options, but does not use all variants these
    #        options can be written. So just a rough test ...
    #
    # NOTE: Some commands may have invalid arguments (i.e. --sep=CHAR ) or
    #       the commands may be unknown. This results in  **WARNING  texts
    #       for the correspoding commands.

    if ($cfg{'trace'} + $cfg{'traceARG'} + $cfg{'verbose'} <= 0) {
        #_warn("831: +quit  command usefull with --v and/or --trace* option only");
        _warn("831: +quit  command should be used with  --trace=arg  option");
    }
    $cfg{'verbose'} = 2 if ($cfg{'verbose'} < 2);   # dirty hack
    $cfg{'trace'}   = 2 if ($cfg{'trace'}   < 2);   # -"-
    $cfg{'traceARG'}= 1; # for _yeast_args()
    print("\n# +quit using:  --verbode=2 --trace=2 --traceARG");
    _v_print("\n# +quit : some information may appear multiple times\n#");
    _yeast_init();
    # _yeast_args();  # duplicate call, see in main at "set environment"
    print "# TEST done.";
    return;
} # printquit

sub __SSLeay        {
    #? internal wrapper for Net::SSLeay::SSLeay()
    if (1.49 > $Net::SSLeay::VERSION) {
        my $txt  = "ancient version Net::SSLeay $Net::SSLeay::VERSION < 1.49;";
           $txt .= " cannot compare SSLeay with openssl version";
        warn STR_WARN, "080: $txt";         # not _warn(), SEE Perl:warn
        return "$Net::SSLeay::VERSION";
    } else {
        return Net::SSLeay::SSLeay();
    }
} # __SSLeay

sub printversionmismatch {
    #? check if openssl and compiled SSLeay are of same version
    my $o = Net::SSLeay::OPENSSL_VERSION_NUMBER();
    my $s = __SSLeay();
    if ($o ne $s) {
        _warn("841: used openssl version '$o' differs from compiled Net:SSLeay '$s'; ignored");
    }
    return;
} # printversionmismatch

## no critic qw(Subroutines::ProhibitExcessComplexity)
#  NOTE: yes, it is high complexity, but that's the nature of printing all information
sub printversion    {
    #? print program and module versions
    local $\ = "\n";
    if ($cfg{'verbose'} > 0) {
        print "# perl $^V";
        print '# @INC = ' . join(" ", @INC) . "\n";
    }
    print( "=== started in: $ENV{PWD} ===");# avoid "use Cwd;" or `pwd`
    # SEE Note:OpenSSL Version
    my $version_openssl  = Net::SSLeay::OPENSSL_VERSION_NUMBER() || STR_UNDEF;
    print( "=== $0 $VERSION ===");
    print( "    osaft_vm_build = $ENV{'osaft_vm_build'}") if (defined $ENV{'osaft_vm_build'});
    print( "    Net::SSLeay::");    # next two should be identical
    printf("       ::OPENSSL_VERSION_NUMBER()    0x%x (%s)\n", $version_openssl, $version_openssl);
    printf("       ::SSLeay()                    0x%x (%s)\n", __SSLeay(), __SSLeay());
    if (1.49 > $Net::SSLeay::VERSION) {
        _warn("851: ancient version Net::SSLeay $Net::SSLeay::VERSION < 1.49; detailed version not available");
    } else {
      if ($cfg{'verbose'} > 0) {
        # TODO: not all versions of Net::SSLeay have constants like
        # Net::SSLeay::SSLEAY_CFLAGS, hence we use hardcoded integers
        print "       ::SSLEAY_DIR                  " . Net::SSLeay::SSLeay_version(5);
        print "       ::SSLEAY_BUILD_ON             " . Net::SSLeay::SSLeay_version(3);
        print "       ::SSLEAY_PLATFORM             " . Net::SSLeay::SSLeay_version(4);
        print "       ::SSLEAY_CFLAGS               " . Net::SSLeay::SSLeay_version(2);
      }
      print "    Net::SSLeay::SSLeay_version()    " . Net::SSLeay::SSLeay_version(); # no parameter is same as parameter 0
      # TODO: print "   *SSL version mismatch" if Net::SSLeay::SSLeay_version() ne Net::SSLinfo::do_openssl('version','','','');
    }

    print "= openssl =";
    print "    external executable              " . (($cmd{'openssl'} eq "") ? "<<executable not found>>" : $cmd{'openssl'});
    print "    version of external executable   " . Net::SSLinfo::do_openssl('version', '', '', '');
    print "    used environment variable (name) " . $cmd{'envlibvar'};
    print "    environment variable (content)   " . ($ENV{$cmd{'envlibvar'}} || STR_UNDEF);
    print "    path to shared libraries         " . join(" ", @{$cmd{'libs'}});
    if (scalar @{$cmd{'libs'}} > 0) {
        foreach my $l (qw(libcrypto.a libcrypto.so libssl.a libssl.so)) {
           foreach my $p (@{$cmd{'libs'}}) {
               my $lib = "$p/$l";
                  $lib = "<<$p/$l not found>>" if (! -e $lib);
               print "    library                          " . $lib;
               if ($cfg{'verbose'} > 1) {
                   print "#   strings $lib | grep 'part of OpenSSL')";
                   print qx(strings $lib | grep 'part of OpenSSL');
               }
           }
        }
    }
    print "    full path to openssl.cnf file    " . ($cfg{'openssl_cnf'} || STR_UNDEF);
    print "    common openssl.cnf files         " . join(" ", @{$cfg{'openssl_cnfs'}});
    print "    URL where to find CRL file       " . ($cfg{'ca_crl'}  || STR_UNDEF);
    print "    directory with PEM files for CAs " . ($cfg{'ca_path'} || STR_UNDEF);
    print "    PEM format file with CAs         " . ($cfg{'ca_file'} || STR_UNDEF);
    print "    common paths to PEM files for CAs ". join(" ", @{$cfg{'ca_paths'}});
    if ($cfg{'verbose'} > 0) {
        foreach my $p (@{$cfg{'ca_paths'}}) {
            print "       existing path to CA PEM files " . $p if -e $p;
        }
    }
    print "    common PEM filenames for CAs     " . join(" ", @{$cfg{'ca_files'}});
    if ($cfg{'verbose'} > 0) {
        foreach my $p (@{$cfg{'ca_paths'}}) {
            foreach my $f (@{$cfg{'ca_files'}}) {
                print "       existing PEM file for CA      " . "$p/$f" if -e "$p/$f";
            }
        }
    }
    my @ciphers= Net::SSLinfo::cipher_openssl();# openssl ciphers ALL:aNULL:eNULL
    my $cnt    = 0;
       $cnt    = @ciphers if (not grep{/<<openssl>>/} @ciphers);# if executable found
    print "    number of supported ciphers      " . $cnt;
    print "    list of supported ciphers        " . join(" ", @ciphers) if ($cfg{'verbose'} > 0);
    print "    openssl supported SSL versions   " . join(" ", @{$cfg{'version'}});
    print "    $me known SSL versions     "       . join(" ", @{$cfg{'versions'}});
    printversionmismatch();

    print "= $me +cipher =";
    print "    list of supported elliptic curves " . join(" ", @{$cfg{'ciphercurves'}});
    print "    list of supported ALPN, NPN      " . join(" ", $cfg{'protos_next'});
    if ($cfg{'verbose'} > 0) {
        print "    list of supported ALPN       " . join(" ", @{$cfg{'protos_alpn'}});
        print "    list of supported NPN        " . join(" ", @{$cfg{'protos_npn'}});
    }

    print "= $me +cipherall ="; # +cipherraw
    # TODO: would be nicer:   $cfg{'cipherranges'}->{'rfc'} =~ s/\n//g;
    print "    default list of ciphers          " . $cfg{'cipherranges'}->{'rfc'};
    if ($cfg{'verbose'} > 0) {
        # these lists are for special purpose, so with --v only
        print "    long list of ciphers         " . $cfg{'cipherranges'}->{'long'};
        print "    huge list of ciphers         " . $cfg{'cipherranges'}->{'huge'};
        print "    safe list of ciphers         " . $cfg{'cipherranges'}->{'safe'};
        print "    full list of ciphers         " . $cfg{'cipherranges'}->{'full'};
        print "    C0xx list, range C0xx..C0FF  " . $cfg{'cipherranges'}->{'c0xx'};
        print "    CCxx list, range CCxx..CCFF  " . $cfg{'cipherranges'}->{'c0xx'};
        print "    ECC list, ephermeral ciphers " . $cfg{'cipherranges'}->{'ecc'};
        print "    SSLv2 list of ciphers        " . $cfg{'cipherranges'}->{'SSLv2'};
        print "    SSLv2_long list of ciphers   " . $cfg{'cipherranges'}->{'SSLv2_long'};
        print "    shifted list of ciphers      " . $cfg{'cipherranges'}->{'shifted'};
    }

# TODO: i.g. OPENSSL_VERSION_NUMBER() returns same value as SSLeay()
#       but when using libraries with LD_LIBRARY_PATH or alike, these
#       versions differ

    # get a quick overview also
    # SEE Perl:import include
    print "= Required (and used) Modules =";
    print '    @INC                 ', "@INC";
    my ($d, $v, %p);
    printf("=   %-22s %-9s%s\n", "module name", "VERSION", "found in");
    printf("=   %s+%s+%s\n",     "-"x22,        "-"x8,     "-"x42);
    # TODO: following list should be same as in _check_modules()
    foreach my $m (qw(IO::Socket::INET IO::Socket::SSL Time::Local Net::DNS Net::SSLeay Net::SSLinfo Net::SSLhello Ciphers osaft)) {
        no strict 'refs';   ## no critic qw(TestingAndDebugging::ProhibitNoStrict TestingAndDebugging::ProhibitProlongedStrictureOverride)
            # avoid: Can't use string ("Net::DNS") as a HASH ref while "strict refs" in use
        # we expect ::VERSION in all these modules
        ($d = $m) =~ s#::#/#g;  $d .= '.pm';# convert string to key for %INC
        $v  = $m . "::VERSION";             # compute module's VERSION variable
        printf("    %-22s %-9s%s\n", $m, ($$v || " "), ($INC{$d} || " "));
            # use a single space if value is not defined
    }
    if ($cfg{'verbose'} > 0) {
        print "\n= Loaded Modules =";
        foreach my $m (sort keys %INC) {
            printf("    %-22s %6s\n", $m, $INC{$m});
            $d = $INC{$m}; $d =~ s#$m$##; $p{$d} = 1;
        }
        print "\n= Loaded Module Versions =";
        no strict 'refs';   ## no critic qw(TestingAndDebugging::ProhibitNoStrict)
            # avoid: Can't use string ("AutoLoader::") as a HASH ref while "strict refs" in use
        foreach my $m (sort keys %main:: ) {
            next if $m !~ /::/;
            $d = "?";       # beat the "Use of uninitialized value" dragon
            $d = ${$$m{'VERSION'}} if defined ${$$m{'VERSION'}};
            printf("    %-22s %6s\n", $m, $d);
        }
    }
    return if ($^O =~ m/MSWin32/); # not Windows
    if ($cfg{'verbose'} > 1) {
        print "\n= Used Shared Objects =";
        # quick&dirty, don't want to use ::Find module
        foreach my $d (sort keys %p) {
             next if ($d =~ m/^\s*$/);
             print "# find $d -name SSLeay.so\\* -o -name libssl.so\\* -o -name libcrypto.so\\*";
             print qx(find $d -name SSLeay.so\\* -o -name libssl.so\\* -o -name libcrypto.so\\*);
        }
    }
    return;
} # printversion

sub _hex_like_openssl   {
    # convert full hex constant to format used by openssl's output
    my $c = shift;
    $c =~ s/0x(..)(..)(..)(..)/0x$2,0x$3,0x$4 - /; # 0x0300C029 ==> 0x00,0xC0,0x29
    $c =~ s/^0x00,// if ($c ne "0x00,0x00,0x00");  # first byte omitted if 0x00
    return sprintf("%22s", $c);
} # _hex_like_openssl

sub printciphers        {
    #? print cipher descriptions from internal database
    # uses settings from --legacy= and --format= options to select output format
    # implemented in VERSION 14.07.14

    #                                         # output looks like: openssl ciphers
    if ((($cfg{'ciphers-v'} + $cfg{'ciphers-V'}) <= 0)
     and ($cfg{'legacy'} eq "openssl") and ($cfg{'format'} eq "")) {
        # TODO: filter ciphers not supported by openssl
        _trace("printciphers: +ciphers");
        print join(":", (keys %ciphers));
        return;
    }

    # anything else prints user-specified formats
    _trace("printciphers: +list");
    my $sep = $text{'separator'};
    my ($hex,  $ssl,  $tag,  $bit,  $aut,  $enc,  $key,  $mac);
        $hex = $ssl = $tag = $bit = $aut = $enc = $key = $mac = "";
    _v_print("command: " . join(" ", @{$cfg{'do'}}));
    _v_print("database version: $VERSION");
    _v_print("options: --legacy=$cfg{'legacy'} , --format=$cfg{'format'} , --header=$cfg{'out_header'}");
    _v_print("options: --v=$cfg{'verbose'}, -v=$cfg{'ciphers-v'} , -V=$cfg{'ciphers-V'}");
    my $have_cipher = 0;
    my $miss_cipher = 0;
    my $ciphers     = "";
       $ciphers     = Net::SSLinfo::cipher_openssl() if ($cfg{'verbose'} > 0);

    printheader(_get_text('out_list', $0), "");
    # all following headers printed directly instead of using printheader()

    if ($cfg{'legacy'} eq "ssltest") {      # output looks like: ssltest --list
        _warn("861: not all ciphers listed");
        foreach my $ssl (qw(SSLv2 SSLv3 TLSv1)) {# SSLv3 and TLSv1 are the same, hence search both
          print "SSLv2 Ciphers Supported..."       if ($ssl eq 'SSLv2');
          print "SSLv3/TLSv1 Ciphers Supported..." if ($ssl eq 'SSLv3');
          foreach my $c (sort keys %ciphers) {
            next if ($ssl ne get_cipher_ssl($c));
            $aut =  get_cipher_auth($c); $aut =  "No" if ($aut =~ /none/i);
            $key =  get_cipher_keyx($c); $key =~ s/[()]//g;
            $mac =  get_cipher_mac($c);
            $enc =  get_cipher_enc($c);
            $bit =  get_cipher_bits($c);
            if ($bit =~ m/\d+/) {           # avoid Perl warning "Argument isn't numeric"
                $bit = sprintf("%03d", $bit);
            } else {                        # pretty print
                $bit = '-?-';
                $bit = '000' if ($enc =~ m/None/i);
            }
            printf("   %s, %s %s bits, %s Auth, %s MAC, %s Kx\n",
                $c, $enc, $bit, $aut, $mac, $key,
            );
          }
        }
    }

    if ($cfg{'legacy'} eq "openssl") {      # output looks like: openssl ciphers -[v|V]
        foreach my $c (sort keys %ciphers) {
            $hex = _hex_like_openssl(get_cipher_hex($c)) if ($cfg{'ciphers-V'} > 0); # -V
            $ssl =  get_cipher_ssl($c);  $ssl =~ s/^(TLSv1)(\d)$/$1.$2/;   # openssl has a .
            $bit =  get_cipher_bits($c); $bit =  "($bit)" if ($bit ne ""); # avoid single :
            $tag =  get_cipher_tags($c); $tag =~ s/^\s*:\s*$//;            # avoid single :
            $aut =  get_cipher_auth($c);
            $key =  get_cipher_keyx($c);
            $mac =  get_cipher_mac($c);
            $enc =  get_cipher_enc($c);
            if ($sep eq " ") {
                # spaces are the default separator in openssl's output
                # spaces are the default separator for --legacy=openssl too if
                # not explicitely specified with  --sep=
                # if we use spaces, additonal formatting needs to be spaces too
                $ssl = sprintf("%-5s", $ssl);
                $aut = sprintf("%-4s", $aut);
                $key = sprintf("%-8s", $key);
                $mac = sprintf("%-4s", $mac);
            }
            printf("%s%-23s%s%s%sKx=%s%sAu=%s%sEnc=%s%s%sMac=%s%s%s\n",
                $hex, $c, $sep, $ssl, $sep, $key, $sep, $aut, $sep,
                $enc, $bit, $sep, $mac, $sep, $tag,
            );
        }
    }

    if ($cfg{'legacy'} eq "simple") { # this format like for +list up to VERSION 14.07.14
        $sep = "\t";
        if ($cfg{'out_header'} > 0) {
            printf("= %-30s %s\n", "cipher", join($sep, @{$ciphers_desc{'head'}}));
            printf("=%s%s\n", ('-' x 30), ('+-------' x 9));
        }
        foreach my $c (sort keys %ciphers) {
            printf(" %-30s %s\n", $c, join($sep, @{$ciphers{$c}}));
        }
        if ($cfg{'out_header'} > 0) {
            printf("=%s%s\n", ('-' x 30), ('+-------' x 9));
        }
    }

    if ($cfg{'legacy'} eq "full") {
        $sep = $text{'separator'};
        if ($cfg{'out_header'} > 0) {
            printf("= Constant$sep%s%-20s${sep}Aliases\n",   "Cipher", join($sep, @{$ciphers_desc{'text'}}));
            printf("= constant$sep%-30s$sep%s${sep}alias\n", "cipher", join($sep, @{$ciphers_desc{'head'}}));
            printf("=--------------+%s%s\n", ('-' x 31), ('+-------' x 10));
        }
        foreach my $c (sort keys %ciphers) {
            my $can = " "; # FIXME
            if ($cfg{'verbose'} > 0) {
                if (0 >= (grep{$_ eq $c} split(/:/, $ciphers))) {
                    $can = "#";
                    $miss_cipher++;
                } else {
                    $have_cipher++;
                }
            }
            $hex = get_cipher_hex($c);
            my $alias = "";
               $alias = join(" ", @{$cipher_alias{$hex}}) if (defined $cipher_alias{$hex});
            $hex = sprintf("%s$sep", ($hex || "    -?-"));
            printf("%s %s%-30s$sep%s$sep%s\n", $can, $hex, $c, join($sep, @{$ciphers{$c}}), $alias);
        }
        if ($cfg{'out_header'} > 0) {
            printf("=--------------+%s%s\n", ('-' x 31), ('+-------' x 10));
        }
        if ($cfg{'verbose'} > 0) {
            my @miss = ();
            my @test = ();
            my $dupl = ""; # need to identify duplicates as we don't have List::MoreUtils
            foreach my $c (split(/:/, $ciphers)) {
                next if ($c eq $dupl);
                push(@test, $c) if     defined $ciphers{$c};
                push(@miss, $c) if not defined $ciphers{$c};
                $dupl = $c;
            }
            # no customizable texts from %text, as it's for --v only
            print "\n# Ciphers marked with # above are not supported by local SSL implementation.\n";
            print "Supported Ciphers:        ",  $have_cipher;
            print "Unsupported Ciphers:      ",  $miss_cipher;
            print "Testable Ciphers:         ",  scalar(@test);
            print "Ciphers missing in $me: ",    scalar(@miss), "  ", join(" ", @miss) if (scalar(@miss) > 0);
            print "Ciphers in alias list:    ",  scalar(keys %cipher_alias); # FIXME: need to count values
        }
    }

    return;
} # printciphers

sub printscores         {
    #? print calculated score values
    my ($legacy, $host, $port) = @_;
    scoring($host, $port);
    # simple rounding in Perl: $rounded = int($float + 0.5)
    $scores{'checks'}->{val} = int(
            ((
              $scores{'check_cert'}->{val}
            + $scores{'check_conn'}->{val}
            + $scores{'check_dest'}->{val}
            + $scores{'check_http'}->{val}
            + $scores{'check_size'}->{val}
            ) / 5 ) + 0.5);
    printheader($text{'out_scoring'}."\n", $text{'desc_score'});
    _trace_cmd('%scores');
    foreach my $key (sort keys %scores) {
        next if ($key !~ m/^check_/); # print totals only
        print_line($legacy, $host, $port, $key, $scores{$key}->{txt}, $scores{$key}->{val});
    }
    print_line($legacy, $host, $port, 'checks', $scores{'checks'}->{txt}, $scores{'checks'}->{val});
    printruler();
    if (($cfg{'traceKEY'} > 0) && ($verbose > 0)) {
        _y_CMD("verbose score table");
        print "\n";
        printtable('score');
        printruler();
    }
    return;
} # printscores

sub printopenssl        {
    #? print openssl version
    print Net::SSLinfo::do_openssl('version', '', '', '');
    printversionmismatch();
    return;
} # printopenssl

sub printusage_exit     {
    my @txt = @_;
    local $\ = "\n";
    print STR_USAGE, @txt;
    print "# most common usage:
  $me +info     your.tld
  $me +check    your.tld
  $me +cipher   your.tld
  $me +cipherll your.tld
# for more help use:
  $me --help
    ";
    exit 2;
} # printusage_exit

sub _get_host_port      {
    #? check argument and return host:port
    # allow host, host:port, URL with IPv4, IPv6, FQDN
    #   http://user:pass@f.q.d.n:42/aa*foo=bar:23/
    #    ftp://username:password@hostname/
    #   http://f.q.d.n:42/aa*foo=bar:23/
    #    ftp://f.q.d.n:42/aa*foo=bar:23
    #   ftp:42/no-fqdn:42/aa*foo=bar:23
    #   //abc/def    
    #   abc://def    # scary
    # NOTE: following regex allow hostnames containing @, _ and many more ...
    my $arg   =  shift;
    my $prot  =  $arg;
    my $host  =  $arg;
       $host  =~ s#^(?:[a-z][a-z0-9]*:)?//##i; # strip schema, if any
       $host  =~ s#^(?:[^@]+@)?##i;            # strip user:pass, if any
       $host  =~ s#/.*$##;                     # strip /path/and?more
    return "" if ($host =~ m/^\s*$/);
    my $port  =  $host;
       $port  =~ s#^.*:([0-9]+)$#$1#;          # get port
       $port  =  $cfg{'port'}  if ($port =~ m/^\s*$/);
       $port  =  $cfg{'port'}  if ($port eq $host); # use previous port
       $host  =~ s#(?::[0-9]+)$##;             # strip port
    _y_ARG("arg=$arg => host=$host, port=$port");
    return "" if ($port =~ m/^\s*$/);
    return "$host:$port";
} # _get_host_port

# end sub

usr_pre_args();

#| scan options and arguments
#| -------------------------------------
# All arguments are  inspected here.  We do not use any module,  like Getopt,
# 'cause we want to support various variants of the same argument,  like case
# sensitive or additional characters i.e.  .  -  _  to be ignored, and so on.
# This also allows to use  different options and commands easily for the same
# functionality without defining each variant. Grep for "alias" below ...
# Even most commands are also the key in our own data structure (%data, %cfg)
# we do not use any argument as key drectly, but always compare with the keys
# and assign values using keys literally, like: $cfg{'key'} = $arg .

my $typ = 'HOST';
push(@argv, "");# need one more argument otherwise last --KEY=VALUE will fail
while ($#argv >= 0) {
    $arg = shift @argv;
    _y_ARG("cli_arg= $arg");
    push(@{$dbx{argv}}, $arg) if (($arg !~ m/^--cfg[_-]/) && (($arg =~ m/^[+-]/) || ($typ ne "HOST")));
    push(@{$dbx{cfg}},  $arg) if  ($arg =~ m/^--cfg[_-]/);    # both aprox. match are sufficient for debugging

    # First check for arguments of options.
    # Options are not case sensitive.  Options may contain  .  and  -  and  _
    # anywhere in its name. These characters are silently ignored.  These are
    # all the same:  --no-DNS  --no_DNS  --no.dns  --NoDns  --n-o_D.N.s
    # Options may have an argument, either as separate word or as part of the
    # option parameter itself: --opt argument   or   --opt=argument .
    # Such an argument is handled using $typ. All types except HOST, which is
    # the default, are handled at the begining here (right below). After pro-
    # cessing the argument, $typ is set to HOST again  and next argument will
    # be taken from command line.
    # $typ='HOST' is handled at end of loop, as it may appear anywhere in the
    # command line and does not require an option.
    # Commands are case sensitive  because they are used directly as key in a
    # hash (see %_SSLinfo Net::SSLinfo.pm). Just commands for the tool itself
    # (not those returning collected data) are case insensitive.
    # NOTE: the sequence of following code must be:
    #   1. check argument (otherwise relooped before)
    #   2. check for options (as they may have arguments)
    #      NOTE: unknown remaining options are silently ignored, because they
    #            cannot easily be distinguished from known ones
    #   3. check for commands (as they all start with '+' and we don't expect
    #      any argument starting with '+')
    #   4. check for HOST argument
    # Parsing options see OPTIONS below, parsing commands see COMMANDS below.

    if ($typ ne 'HOST') { # option arguments
        # Note that $arg already contains the argument
        # hence `next' at end of surrounding if()
        # $type is set at end of  each matching if condition,  hence only the
        # first matching if condition is executed; sequence is important!
        _y_ARG("argument? $arg, typ= $typ");
        push(@{$dbx{exe}}, join("=", $typ, $arg)) if ($typ =~ m/OPENSSL|ENV|EXE|LIB/);
        #  $typ = '????'; # expected next argument
        #  +---------+----------+------------------------------+--------------------
        #   argument to process   what to do                    expect next argument
        #  +---------+----------+------------------------------+--------------------
        if ($typ eq 'CFG-CIPHER') { _cfg_set_cipher($typ, $arg);$typ = 'HOST'; }
        if ($typ =~ m/^CFG/)    { _cfg_set($typ, $arg);         $typ = 'HOST'; }
           # backward compatibility removed to allow mixed case texts;
           # until 16.01.31 lc($arg) was used for pre 14.10.13 compatibility
        if ($typ eq 'VERBOSE')  { $cfg{'verbose'}   = $arg;     $typ = 'HOST'; }
        if ($typ eq 'ENV')      { $cmd{'envlibvar'} = $arg;     $typ = 'HOST'; }
        if ($typ eq 'OPENSSL')  { $cmd{'openssl'}   = $arg;     $typ = 'HOST'; }
        if ($typ eq 'SSLCNF')   { $cfg{'openssl_cnf'}   = $arg; $typ = 'HOST'; }
        if ($typ eq 'SSLFIPS')  { $cfg{'openssl_fips'}  = $arg; $typ = 'HOST'; }
        if ($typ eq 'DO')       { push(@{$cfg{'do'}}, $arg);    $typ = 'HOST'; } # treat as command,
        if ($typ eq 'NO_OUT')   { push(@{$cfg{'ignore-out'}}, $arg);        $typ = 'HOST'; }
        if ($typ eq 'EXE')      { push(@{$cmd{'path'}}, $arg);  $typ = 'HOST'; }
        if ($typ eq 'LIB')      { push(@{$cmd{'libs'}}, $arg);  $typ = 'HOST'; }
        if ($typ eq 'CALL')     { push(@{$cmd{'call'}}, $arg);  $typ = 'HOST'; }
        if ($typ eq 'CIPHER')   { push(@{$cfg{'cipher'}}, $arg);$typ = 'HOST'; }
        if ($typ eq 'SEP')      { $text{'separator'}= $arg;     $typ = 'HOST'; }
        if ($typ eq 'OPT')      { $cfg{'sclient_opt'}.=" $arg"; $typ = 'HOST'; }
        if ($typ eq 'TIMEOUT')  { $cfg{'timeout'}   = $arg;     $typ = 'HOST'; }
        if ($typ eq 'CTXT')     { $cfg{'no_cert_txt'}= $arg;    $typ = 'HOST'; }
        if ($typ eq 'CAFILE')   { $cfg{'ca_file'}   = $arg;     $typ = 'HOST'; }
        if ($typ eq 'CAPATH')   { $cfg{'ca_path'}   = $arg;     $typ = 'HOST'; }
        if ($typ eq 'CADEPTH')  { $cfg{'ca_depth'}  = $arg;     $typ = 'HOST'; }
        if ($typ eq 'PPORT')    { $cfg{'proxyport'} = $arg;     $typ = 'HOST'; }
        if ($typ eq 'PUSER')    { $cfg{'proxyuser'} = $arg;     $typ = 'HOST'; }
        if ($typ eq 'PPASS')    { $cfg{'proxypass'} = $arg;     $typ = 'HOST'; }
        if ($typ eq 'PAUTH')    { $cfg{'proxyauth'} = $arg;     $typ = 'HOST'; }
        if ($typ eq 'SNINAME')  { $cfg{'sni_name'}  = $arg;     $typ = 'HOST'; }
        if ($typ eq 'FILE_SCLIENT') { $cfg{'data'}->{'file_sclient'} = $arg;$typ = 'HOST'; }
        if ($typ eq 'FILE_CIPHERS') { $cfg{'data'}->{'file_ciphers'} = $arg;$typ = 'HOST'; }
        if ($typ eq 'FILE_PCAP')    { $cfg{'data'}->{'file_pcap'}    = $arg;$typ = 'HOST'; }
        if ($typ eq 'FILE_PEM')     { $cfg{'data'}->{'file_pem'}     = $arg;$typ = 'HOST'; }
        if ($typ eq 'SSLRETRY')     { $cfg{'sslhello'}->{'retry'}    = $arg;$typ = 'HOST'; }
        if ($typ eq 'SSLTOUT')      { $cfg{'sslhello'}->{'timeout'}  = $arg;$typ = 'HOST'; }
        if ($typ eq 'MAXCIPHER')    { $cfg{'sslhello'}->{'maxciphers'}=$arg;$typ = 'HOST'; }
        if ($typ eq 'SSLERROR_MAX') { $cfg{'sslerror'}->{'max'}      = $arg;$typ = 'HOST'; }
        if ($typ eq 'SSLERROR_TOT') { $cfg{'sslerror'}->{'total'}    = $arg;$typ = 'HOST'; }
        if ($typ eq 'SSLERROR_DLY') { $cfg{'sslerror'}->{'delay'}    = $arg;$typ = 'HOST'; }
        if ($typ eq 'SSLERROR_TOUT'){ $cfg{'sslerror'}->{'timeout'}  = $arg;$typ = 'HOST'; }
        if ($typ eq 'SSLERROR_PROT'){ $cfg{'sslerror'}->{'per_prot'} = $arg;$typ = 'HOST'; }
        if ($typ eq 'CONNECT_DLY')  { $cfg{'connect_delay'}     = $arg;     $typ = 'HOST'; }
        if ($typ eq 'STARTTLS') { $cfg{'starttls'}              = $arg;     $typ = 'HOST'; }
        if ($typ eq 'TLSDELAY') { $cfg{'starttls_delay'}        = $arg;     $typ = 'HOST'; }
        if ($typ eq 'SLOWDELAY'){ $cfg{'slow_server_delay'}     = $arg;     $typ = 'HOST'; }
        if ($typ eq 'STARTTLSE1'){$cfg{'starttls_error'}[1]     = $arg;     $typ = 'HOST'; }
        if ($typ eq 'STARTTLSE2'){$cfg{'starttls_error'}[2]     = $arg;     $typ = 'HOST'; }
        if ($typ eq 'STARTTLSE3'){$cfg{'starttls_error'}[3]     = $arg;     $typ = 'HOST'; }
        if ($typ eq 'STARTTLSP1'){$cfg{'starttls_phase'}[1]     = $arg;     $typ = 'HOST'; }
        if ($typ eq 'STARTTLSP2'){$cfg{'starttls_phase'}[2]     = $arg;     $typ = 'HOST'; }
        if ($typ eq 'STARTTLSP3'){$cfg{'starttls_phase'}[3]     = $arg;     $typ = 'HOST'; }
        if ($typ eq 'STARTTLSP4'){$cfg{'starttls_phase'}[4]     = $arg;     $typ = 'HOST'; }
        if ($typ eq 'STARTTLSP5'){$cfg{'starttls_phase'}[5]     = $arg;     $typ = 'HOST'; }
        if ($typ eq 'PORT')     { $cfg{'port'}      = $arg;     $typ = 'HOST'; }
        #if ($typ eq 'HOST')    # not done here, but at end of loop
            #  ------+----------+------------------------------+--------------------
        if ($typ eq 'STD_FORMAT') {
            if ($arg =~ /^(?:unix|raw|crlf|utf8|win32|perlio)$/) {
                _set_binmode($arg);
            } else {
                _set_binmode(":encoding($arg)") if ($arg =~ /^[a-zA-Z0-9_.-]+$/);
                    # simple input validation
            }
        }
        if ($typ eq 'PROTOCOL') {
            if ($arg =~ /^?sslv?2$/i)         { $cfg{'SSLv2'}   = 1; }
            if ($arg =~ /^?sslv?3$/i)         { $cfg{'SSLv3'}   = 1; }
            if ($arg =~ /^?tlsv?1$/i)         { $cfg{'TLSv1'}   = 1; }
            if ($arg =~ /^?tlsv?1[-_.]?1$/i)  { $cfg{'TLSv11'}  = 1; }
            if ($arg =~ /^?tlsv?1[-_.]?2$/i)  { $cfg{'TLSv12'}  = 1; }
            if ($arg =~ /^?tlsv?1[-_.]?3$/i)  { $cfg{'TLSv13'}  = 1; }
            if ($arg =~ /^dtlsv?0[-_.]?9$/i)  { $cfg{'DTLSv09'} = 1; }
            if ($arg =~ /^dtlsv?1[-_.]?0?$/i) { $cfg{'DTLSv1'}  = 1; }
            if ($arg =~ /^dtlsv?1[-_.]?1$/i)  { $cfg{'DTLSv11'} = 1; }
            if ($arg =~ /^dtlsv?1[-_.]?2$/i)  { $cfg{'DTLSv12'} = 1; }
            if ($arg =~ /^dtlsv?1[-_.]?3$/i)  { $cfg{'DTLSv13'} = 1; }
            $typ = 'HOST';
        }
        if ($typ eq 'PHOST')    {
            # allow   user:pass@f.q.d.n:42
            $cfg{'proxyhost'} = $arg;
            if ($arg =~ m#([^@]*)@(.*)#) {              # got username:password
                $arg =  $2;
                if ($1 =~ m#([^:@]*?):([^@]*)#) {
                    $cfg{'proxyuser'} = $1;
                    $cfg{'proxypass'} = $2;
                }
            }
            if ($arg =~ m#([^:]*):(\d+)#) {             # got a port too
                $cfg{'proxyhost'} = $1;
                $cfg{'proxyport'} = $2;
            # else port must be given by --proxyport
            }
            $typ = 'HOST';
        }
        # following ($arg !~ /^\s*$/) check avoids warnings in CGI mode
        if ($typ eq 'LEGACY')   {
            $arg = 'sslcipher' if ($arg eq 'ssl-cipher-check'); # alias
            if (1 == (grep{/^$arg$/i} @{$cfg{'legacys'}})) {
                $cfg{'legacy'} = lc($arg);
            } else {
                _warn("054: option with unknown legacy '$arg'; setting ignored") if ($arg !~ /^\s*$/);
            }
        }
        if ($typ eq 'FORMAT')   {
            $arg = 'esc' if ($arg =~ m#^[/\\]x$#);      # \x and /x are the same
            if (1 == (grep{/^$arg$/} @{$cfg{'formats'}})) {
                $cfg{'format'} = $arg;
            } else {
                _warn("055: option with unknown format '$arg'; setting ignored") if ($arg !~ /^\s*$/);
            }
        }
        if ($typ eq 'CRANGE')   {
            if (1 == (grep{/^$arg$/} keys %{$cfg{'cipherranges'}})) {
                $cfg{'cipherrange'} = $arg;
            } else {
                _warn("056: option with unknown cipher range '$arg'; setting ignored") if ($arg !~ /^\s*$/);
            }
        }
        if ($typ eq 'CURVES')   {
            $cfg{'ciphercurves'} = [""] if ($arg =~ /^[,:][,:]$/);# special to set empty string
            if ($arg =~ /^[,:]$/) {
                $cfg{'ciphercurves'} = [];
            } else {
                push(@{$cfg{'ciphercurves'}}, split(/,/, $arg));
            }
            # TODO: checking names of curves needs a sophisticated function
            #if (1 == (grep{/^$arg$/} keys %{$cfg{'ciphercurves'}})) {
            #    $cfg{'ciphercurves'} = $arg;
            #} else {
            #    _warn("057: option with unknown curve name '$arg'; setting ignored") if ($arg !~ /^\s*$/);
            #}
        }

        # SEE Note:ALPN, NPN
        # --protos* is special to simulate empty and undefined arrays
        #   --protosnpn=value   - add value to array
        #   --protosnpn=,       - set empty array
        #   --protosnpn=,,      - set array element to ""
        # NOTE: distinguish:  [], [""], [" "]
        if ($typ eq 'CIPHER_ALPN'){
            $cfg{'cipher_alpns'} = [""] if ($arg =~ /^[,:][,:]$/);# special to set empty string
            if ($arg =~ /^[,:]$/) {
                $cfg{'cipher_alpns'} = [];
            } else {
                push(@{$cfg{'cipher_alpns'}}, split(/,/, $arg));
            }
            # TODO: checking names of protocols needs a sophisticated function
            #if (1 == (grep{/^$arg$/} split(/,/, $cfg{'protos_next'})) { }
        }
        if ($typ eq 'CIPHER_NPN'){
            $cfg{'cipher_npns'} = [""] if ($arg =~ /^[,:][,:]$/);# special to set empty string
            if ($arg =~ /^[,:]$/) {
                $cfg{'cipher_npns'} = [];
            } else {
                push(@{$cfg{'cipher_npns'}},  split(/,/, $arg));
            }
            # TODO: checking names of protocols needs a sophisticated function
        }
        if ($typ eq 'PROTO_ALPN'){
            $cfg{'protos_alpn'} = [""] if ($arg =~ /^[,:][,:]$/);# special to set empty string
            if ($arg =~ /^[,:]$/) {
                $cfg{'protos_alpn'} = [];
            } else {
                push(@{$cfg{'protos_alpn'}}, split(/,/, $arg));
            }
            # TODO: checking names of protocols needs a sophisticated function
            #if (1 == (grep{/^$arg$/} split(/,/, $cfg{'protos_next'})) { }
        }
        if ($typ eq 'PROTO_NPN'){
            $cfg{'protos_npn'} = [""] if ($arg =~ /^[,:][,:]$/);# special to set empty string
            if ($arg =~ /^[,:]$/) {
                $cfg{'protos_npn'} = [];
            } else {
                push(@{$cfg{'protos_npn'}},  split(/,/, $arg));
            }
            # TODO: checking names of protocols needs a sophisticated function
        }
        _y_ARG("argument= $arg");

        # --trace is special for historical reason, we allow:
        #   --traceARG
        #   --tracearg
        #   --trace=arg
        #   --trace arg
        #   --trace=2
        #   --trace 2
        #   --trace=me
        #   --traceME
        # problem is that we historically allow also
        #   --trace
        # which has no argument, hence following checks for valid arguments
        # and pass it to further examination if it not matches
        if ($typ eq 'TRACE')    {
            $typ = 'HOST';      # expect host as next argument
            $cfg{'traceARG'}++   if ($arg =~ m#^ARG$#i);
            $cfg{'traceCMD'}++   if ($arg =~ m#^CMD$#i);
            $cfg{'traceKEY'}++   if ($arg =~ m#^KEY$#i);
            $cfg{'traceTIME'}++  if ($arg =~ m#^TIME$#i);
            $cfg{'traceME'}++    if ($arg =~ m#^ME(?:only)?#i);
            $cfg{'traceME'}--    if ($arg =~ m#^notme$#i);
            $cfg{'trace'} = $arg if ($arg =~ m#^\d+$#i);
            # now magic starts ...
            next if ($arg =~ m#^(ARG|CMD|KEY|ME|TIME|\d+)$#i); # matched before
            # if we reach here, argument did not match valid value for --trace,
            # then simply increment trace level and push back argument
            $cfg{'trace'}++;
            unshift(@argv, $arg);
        } # else $typ handled before if-condition
        $typ = 'HOST';          # expect host as next argument
        next;
    } # ne 'HOST' option arguments

    next if ($arg =~ /^\s*$/);# ignore empty arguments

    # remove trailing = for all options
    # such options are incorrectly used, or are passed in in CGI mode
    # NOTE: this means that we cannot have empty strings as value
    if ($arg =~ m/^-[^=]*=$/) {
        # SEE Note:CGI mode
        # only options in RegEx are ignored if the value is empty
        if ($arg =~ /$cfg{'regex'}->{'opt-empty'}/) {
            _warn("050: option with empty argument '$arg'; option ignored") if ($cgi == 0);
            next;
        }
        $arg =~ s/=+$//;
    }

    # first handle some old syntax for backward compatibility
    if ($arg =~ /^--cfg(cmd|score|text)-([^=]*)=(.*)/) {
        $typ = 'CFG-'.$1; unshift(@argv, $2 . "=" . $3);   # convert to new syntax
        _warn("022: old (pre 13.12.12) syntax '--cfg-$1-$2'; converted to '--cfg-$1=$2'; please consider changing your files");
        next; # no more normalisation!
    }
    if ($arg =~ /^--set[_-]?score=(.*)/) {
        _warn("021: old (pre 13.12.11) syntax '--set-score=*' obsolete, please use --cfg-score=*; option ignored");
        next;
    }

    # all options starting with  --usr or --user  are not handled herein
    # push them on $cfg{'usr-args'} so they can be accessd in o-saft-*.pm
    if ($arg =~ /^--use?r/) {
        $arg =~ s/^(?:--|\+)//;     # strip leading chars
        push(@{$cfg{'usr-args'}}, $arg);
        next;
    }

    # all options starting with  --h or --help or +help  are not handled herein
    if ($arg =~ /^(?:--|\+)h(?:elp)?$/)          { $arg = "--help=NAME"; }# --h  or --help
    if ($arg =~ /^\+(abbr|abk|glossar|todo)$/i)  { $arg = "--help=$1"; }  # for historic reason
    # get matching string right of =
    if ($arg =~ /^(?:--|\+)help=?(.*)?$/) {
        # we allow:  --help=SOMETHING  or  +help=SOMETHING
        if (defined $1) {
            $arg = $1 if ($1 !~ /^\s*$/);   # if it was --help=*
        }
        #my  $err = _load_file("o-saft-man.pm", "help file");
        #if ($err ne "") {
        #    die STR_ERROR, "011: $err" unless (-e $arg);
        #}
        # TODO: _load_file() does not yet work, hence following require
        require q{o-saft-man.pm};   ## no critic qw(Modules::RequireBarewordIncludes)
            # include if necessary only; dies if missing
        printhelp($arg);
        exit 0;
    }

    #{ handle some specials
    #!#--------+------------------------+--------------------------+------------
    #!#           argument to check       what to do             what to do next
    #!#--------+------------------------+--------------------------+------------
    if ($arg eq  '--trace--')           { $cfg{'traceARG'}++;       next; } # for backward compatibility
    if ($arg =~ /^--v(?:erbose)?$/)     { $cfg{'verbose'}++;        next; } # --v and --v=X allowed
    if ($arg =~ /^--?starttls$/i)       { $cfg{'starttls'} ="SMTP"; next; } # shortcut for  --starttls=SMTP
    if ($arg =~ /^--cgi.*/)             { $cgi = 1;                 next; } # for CGI mode; ignore
    if ($arg =~ /^--yeast.?prot/)       { _yeast_prot();          exit 0; } # debugging
    if ($arg =~ /^--yeast(.*)/)         { _yeast_data();          exit 0; } # -"-
    if ($arg =~ /^--exit=(.*)/)         {                           next; } # -"-
    if ($arg =~ /^--cmd=\+?(.*)/)       { $arg = '+' . $1;                } # no next;
    if ($arg =~ /^--rc/)                {                           next; } # nothing to do, already handled
        # in CGI mode commands need to be passed as --cmd=* option
    if ($arg eq '--openssl')            { $arg = '--extopenssl';          } # no next; # dirty hack for historic option --openssl
    #!#--------+------------------------+--------------------------+------------
    #} specials

    # normalize options with arguments:  --opt=name --> --opt name
    if ($arg =~ m/(^-[^=]*)=(.*)/) {
        $arg = $1;
        unshift(@argv, $2);
        #_dbx("push to ARGV $2");
    } # $arg now contains option only, no argument

    # normalize option strings:
    #    --opt-name     --> --optname
    #    --opt_name     --> --optname
    #    --opt.name     --> --optname
    $arg =~ s/([a-zA-Z0-9])(?:[_.-])/$1/g if ($arg =~ /^-/);
    #_dbx("normalized= $arg");

    # Following checks use exact matches with 'eq' or RegEx matches with '=~'

    _y_ARG("option?  $arg");
    #{ OPTIONS
    #  NOTE that strings miss - and _ characters (see normalization above)
    #!# You may read the lines as table with columns like: SEE Note:alias
    #!#--------+------------------------+---------------------------+----------
    #!#           option to check         alias for ...               # used by ...
    #!#--------+------------------------+---------------------------+----------
    # first all aliases
    if ($arg eq  '-t')                  { $arg = '--starttls';      } # alias: testssl.sh
    if ($arg eq  '-b')                  { $arg = '--enabled';       } # alias: ssl-cert-check
    if ($arg eq  '-c')                  { $arg = '--capath';        } # alias: ssldiagnose.exe
    if ($arg =~ /^--?CApath/)           { $arg = '--capath';        } # alias: curl, openssl
    if ($arg =~ /^--?CAfile/)           { $arg = '--cafile';        } # alias: openssl
    if ($arg =~ /^--ca(?:cert(?:ificate)?)$/i)  { $arg = '--cafile';} # alias: curl, openssl, wget, ...
    if ($arg =~ /^--cadirectory$/i)     { $arg = '--capath';        } # alias: curl, openssl, wget, ...
    if ($arg =~ /^--fuzz/i)             { $arg = '--cipherrange'; unshift(@argv, 'huge'); } # alias: sslmap
    if ($arg =~ /^--httpget/i)          { $arg = '--http';          } # alias: sslyze
    if ($arg =~ /^--httpstunnel/i)      { $arg = '--proxyhost';     } # alias: sslyze
    if ($arg eq  '--hiderejectedciphers'){$arg = '--nodisabled';    } # alias: sslyze
    if ($arg eq  '--regular')           { $arg = '--http';          } # alias: sslyze
    if ($arg =~ /^--?interval$/)        { $arg = '--timeout';       } # alias: ssldiagnos.exe
    if ($arg =~ /^--?nofailed$/)        { $arg = '--enabled';       } # alias: sslscan
    if ($arg =~ /^--show-?each$/)       { $arg = '--disabled';      } # alias: testssl.sh
    if ($arg =~ /^--(?:no|ignore)cmd$/) { $arg = '--ignoreout';     } # alias:
        # SEE Note:ignore-out
    # /-- next line is a dummy for extracting aliases
   #if ($arg eq  '--protocol')          { $arg = '--SSL';           } # alias: ssldiagnose.exe
    if ($arg eq  '--range')             { $arg = '--cipherrange';   } # alias:
    if ($arg =~ /^--?servername/i)      { $arg = '--sniname/i';     } # alias: openssl
    # options form other programs which we treat as command; see Options vs. Commands also
    if ($arg =~ /^-(e|-each-?cipher)$/) { $arg = '+cipher';         } # alias: testssl.sh
    if ($arg =~ /^-(E|-cipher-?perproto)$/) { $arg = '+cipherall';  } # alias: testssl.sh
    if ($arg =~ /^-(f|-ciphers)$/)      { $arg = '+ciphercheck';    } # alias: testssl.sh (+ciphercheck defined in .o-saft.pl)
    if ($arg =~ /^-(p|-protocols)$/)    { $arg = '+protocols';      } # alias: testssl.sh
    if ($arg =~ /^-(y|-spdy)$/)         { $arg = '+spdy';           } # alias: testssl.sh
    if ($arg =~ /^-(Y|-http2)$/)        { $arg = '+spdy';           } # alias: testssl.sh
    if ($arg =~ /^-(U|-vulnerable)$/)   { $arg = '+vulns';          } # alias: testssl.sh
    if ($arg =~ /^-(B|-heartbleed)$/)   { $arg = '+heartbleed';     } # alias: testssl.sh
    if ($arg =~ /^-(I|-ccs(?:-?injection))$/) { $arg = '+ccs';      } # alias: testssl.sh
    if ($arg =~ /^-(C|-compression|-crime)$/) { $arg = '+compression';# alias: testssl.sh
                                          push(@{$cfg{'do'}}, @{$cfg{'cmd-crime'}}); }
    if ($arg =~ /^-(T|-breach)$/)       { $arg = '+breach';         } # alias: testssl.sh
    if ($arg =~ /^-(O|-poodle)$/)       { $arg = '+poodle';         } # alias: testssl.sh
    if ($arg =~ /^-(F|-freak)$/)        { $arg = '+freak';          } # alias: testssl.sh
    if ($arg =~ /^-(A|-beast)$/)        { $arg = '+beast';          } # alias: testssl.sh
    if ($arg =~ /^-(BB|-robot)$/)       { $arg = '+robot';          } # alias: testssl.sh
    if ($arg =~ /^-(J|-logjam)$/)       { $arg = '+logjam';         } # alias: testssl.sh
    if ($arg =~ /^-(D|-drown)$/)        { $arg = '+drown';          } # alias: testssl.sh
    if ($arg =~ /^--(p?fs|nsa)$/)       { $arg = '+pfs';            } # alias: testssl.sh
    if ($arg =~ /^--(rc4|appelbaum)$/)  { $arg = '+pfs';            } # alias: testssl.sh
    if ($arg eq  '-R')                  { $arg = '+renegotiation';  } # alias: testssl.sh
    if ($arg =~ /^--reneg(?:otiation)?/){ $arg = '+renegotiation';  } # alias: sslyze, testssl.sh
    if ($arg =~ /^--resum(?:ption)?$/)  { $arg = '+resumption';     } # alias: sslyze
    if ($arg eq  '--chain')             { $arg = '+chain';          } # alias:
    if ($arg eq  '--default')           { $arg = '+default';        } # alias:
    if ($arg eq  '--fingerprint')       { $arg = '+fingerprint';    } # alias:
    if ($arg eq  '--fips')              { $arg = '+fips';           } # alias:
    if ($arg eq  '-i')                  { $arg = '+issuer';         } # alias: ssl-cert-check
    if ($arg eq  '--ism')               { $arg = '+ism';            } # alias: ssltest.pl
    if ($arg eq  '--list')              { $arg = '+list';           } # alias: ssltest.pl
    if ($arg eq  '--quit')              { $arg = '+quit';           } # alias:
    if ($arg eq  '--pci')               { $arg = '+pci';            } # alias: ssltest.pl
    if ($arg eq  '--printavailable')    { $arg = '+ciphers';        } # alias: ssldiagnose.exe
    if ($arg eq  '--printcert')         { $arg = '+text';           } # alias: ssldiagnose.exe
    if ($arg =~ /^--showkeys?/i)        { $arg = '--traceKEY';      } # alias:
    if ($arg =~ /^--tracesub/i)         { $arg = '+traceSUB';       } # alias:
    if ($arg eq  '--version')           { $arg = '+version';        } # alias: various programs
#   if ($arg eq  '-v')                  { $typ = 'PROTOCOL';        } # alias: ssl-cert-check # FIXME: not supported; see opt-v and ciphers-v above
    if ($arg eq  '-V')                  { $cfg{'opt-V'}     = 1;    } # .....: ssl-cert-check; will be out_header, see below
    if ($arg eq  '--forceopenssl')      { $arg = '--opensslciphers';    } # alias:
    if ($arg eq  '--cipheropenssl')     { $arg = '--opensslciphers';    } # alias:
    if ($arg eq  '--sclient')           { $arg = '--opensslsclient';    } # alias:
    if ($arg eq  '--nosclient')         { $arg = '--noopensslsclient';  } # alias:
    if ($arg eq  '--sslnouseecc')       { $arg = '--nossluseecc';       } # alias:
    if ($arg eq  '--sslnouseecpoint')   { $arg = '--nossluseecpoint';   } # alias:
    if ($arg eq  '--sslnousereneg')     { $arg = '--nosslusereneg';     } # alias:
    if ($arg eq  '--sslnodoublereneg')  { $arg = '--nossldoublereneg';  } # alias:
    if ($arg eq  '--sslnodatanocipher') { $arg = '--nodataeqnocipher';  } # alias:
    if ($arg eq  '--sslnodataeqnocipher'){$arg = '--nodataeqnocipher';  } # alias:
    if ($arg eq  '--nosslnodataeqnocipher'){$arg = '--nosslnodatanocipher'; } # alias:
    if ($arg eq  '--nomd5cipher')       { $arg = '--nociphermd5';       } # alias: used until VERSION 17.04.17
    if ($arg eq  '--md5cipher')         { $arg = '--ciphermd5';         } # alias: used until VERSION 17.04.17
    #!#--------+------------------------+---------------------------+----------
    #!#           option to check         what to do                  comment
    #!#--------+------------------------+---------------------------+----------
    # options for trace and debug
    if ($arg =~ /^--v(?:erbose)?$/)     { $typ = 'VERBOSE';         }
    if ($arg =~ /^--ciphers?-?v$/)      { $arg = '--v-ciphers';     } # alias:
    if ($arg =~ /^--ciphers?--?v$/)     { $arg = '--v-ciphers';     } # alias:
    if ($arg =~ /^--v-?ciphers?$/)      { $cfg{'v_cipher'}++;       }
    if ($arg =~ /^--warnings?$/)        { $cfg{'warning'}++;        }
    if ($arg =~ /^--nowarnings?$/)      { $cfg{'warning'}   = 0;    }
    if ($arg eq  '--n')                 { $cfg{'try'}       = 1;    }
    if ($arg =~ /^--tracearg/i)         { $cfg{'traceARG'}++;       } # special internal tracing
    if ($arg =~ /^--tracecmd/i)         { $cfg{'traceCMD'}++;       } # ..
    if ($arg =~ /^--trace(@|key)/i)     { $cfg{'traceKEY'}++;       } # ..
    if ($arg =~ /^--traceme/i)          { $cfg{'traceME'}++;        } # ..
    if ($arg =~ /^--tracenotme/i)       { $cfg{'traceME'}--;        } # ..
    if ($arg =~ /^--tracetime/i)        { $cfg{'traceTIME'}++;      } # ..
    if ($arg eq  '--trace')             { $typ = 'TRACE';           }
    if ($arg =~ /^--timeabsolute?/i)    { $cfg{'time_absolut'} = 1; }
    if ($arg eq  '--timerelative')      { $cfg{'time_absolut'} = 0; }
    if ($arg eq  '--linuxdebug')        { $cfg{'--linux_debug'}++;  }
    if ($arg eq  '--slowly')            { $cfg{'slowly'}    = 1;    }
    if ($arg =~ /^--exp(erimental)?$/)  { $cfg{'experimental'} = 1; }
    if ($arg =~ /^--noexp(erimental)?$/){ $cfg{'experimental'} = 0; }
    if ($arg eq  '--filesclient')       { $typ = 'FILE_SCLIENT';    }
    if ($arg eq  '--fileciphers')       { $typ = 'FILE_CIPHERS';    }
    if ($arg eq  '--filepcap')          { $typ = 'FILE_PCAP';       }
    if ($arg eq  '--filepem')           { $typ = 'FILE_PEM';        }
    # proxy options
    if ($arg =~ /^--proxy(?:host)?$/)   { $typ = 'PHOST';           }
    if ($arg eq  '--proxyport')         { $typ = 'PPORT';           }
    if ($arg eq  '--proxyuser')         { $typ = 'PUSER';           }
    if ($arg eq  '--proxypass')         { $typ = 'PPASS';           }
    if ($arg eq  '--proxyauth')         { $typ = 'PAUTH';           }
    if ($arg =~ /^--?starttls$/i)       { $typ = 'STARTTLS';        }
    if ($arg =~ /^--starttlsdelay$/i)   { $typ = 'TLSDELAY';        }
    if ($arg =~ /^--slowserverdelay$/i) { $typ = 'SLOWDELAY';       }
    if ($arg =~ /^--starttlserror1$/i)  { $typ = 'STARTTLSE1';      }
    if ($arg =~ /^--starttlserror2$/i)  { $typ = 'STARTTLSE2';      }
    if ($arg =~ /^--starttlserror3$/i)  { $typ = 'STARTTLSE3';      }
    if ($arg =~ /^--starttlsphase1$/i)  { $typ = 'STARTTLSP1';      }
    if ($arg =~ /^--starttlsphase2$/i)  { $typ = 'STARTTLSP2';      }
    if ($arg =~ /^--starttlsphase3$/i)  { $typ = 'STARTTLSP3';      }
    if ($arg =~ /^--starttlsphase4$/i)  { $typ = 'STARTTLSP4';      }
    if ($arg =~ /^--starttlsphase5$/i)  { $typ = 'STARTTLSP5';      }
    # options form other programs for compatibility
    if ($arg eq  '-v')                  { $cfg{'opt-v'}     = 1;    } # openssl, sets ciphers-v, see below
    if ($arg eq  '-V')                  { $cfg{'opt-V'}     = 1;    } # openssl, sets ciphers-V, see below
    if ($arg eq  '--V')                 { $cfg{'opt-V'}     = 1;    } # for lazy people, not documented
    # options form other programs which we treat as command; see Options vs. Commands also
    if ($arg =~ /^--checks?$/)          { $typ = 'DO';              } # tls-check.pl
    if ($arg =~ /^--(fips|ism|pci)$/i)  {}
    # options to handle external openssl
    if ($arg eq  '--openssl')           { $typ = 'OPENSSL';         }
    if ($arg =~  '--opensslco?nf')      { $typ = 'SSLCNF';          }
    if ($arg eq  '--opensslfips')       { $typ = 'SSLFIPS';         }
    if ($arg eq  '--extopenssl')        { $cmd{'extopenssl'}= 1;    }
    if ($arg eq  '--noopenssl')         { $cmd{'extopenssl'}= 0;    }
    if ($arg eq  '--opensslciphers')    { $cmd{'extciphers'}= 1;    }
    if ($arg eq  '--noopensslciphers')  { $cmd{'extciphers'}= 0;    }
    if ($arg eq  '--opensslsclient')    { $cmd{'extsclient'}= 1;    }
    if ($arg eq  '--noopensslsclient')  { $cmd{'extsclient'}= 0;    }
    if ($arg eq  '--alpn')              { $cfg{'usealpn'}   = 1;    }
    if ($arg eq  '--noalpn')            { $cfg{'usealpn'}   = 0;    }
    if ($arg eq  '--npn')               { $cfg{'usenpn'}    = 1;    }
    if ($arg eq  '--nonpn')             { $cfg{'usenpn'}    = 0;    }
    if ($arg =~ /^--?nextprotoneg$/)    { $cfg{'usenpn'}    = 1;    } # openssl
    if ($arg =~ /^--nonextprotoneg/)    { $cfg{'usenpn'}    = 0;    }
    if ($arg =~ /^--?tlsextdebug$/)     { $cfg{'use_extdebug'}  = 1;}
    if ($arg =~ /^--notlsextdebug/)     { $cfg{'use_extdebug'}  = 0;}
    if ($arg =~ /^--?reconnect$/)       { $cfg{'use_reconnect'} = 1;}
    if ($arg =~ /^--noreconnect$/)      { $cfg{'use_reconnect'} = 0;}
    if ($arg eq  '--sclientopt')        { $typ = 'OPT';             }
    # various options
    if ($arg eq  '--forcesni')          { $cfg{'forcesni'}  = 1;    }
    if ($arg =~ /^--ignorenoconn(ect)?/){ $cfg{'sslerror'}->{'ignore_no_conn'}  = 1;}
    if ($arg =~ /^--ignorehandshake/)   { $cfg{'sslerror'}->{'ignore_handshake'}= 1;}
    if ($arg =~ /^--noignorehandshake/) { $cfg{'sslerror'}->{'ignore_handshake'}= 0;}
    if ($arg eq  '--lwp')               { $cfg{'uselwp'}    = 1;    }
    if ($arg eq  '--sni')               { $cfg{'usesni'}    = 1;    }
    if ($arg eq  '--nosni')             { $cfg{'usesni'}    = 0;    }
    if ($arg eq  '--snitoggle')         { $cfg{'usesni'}    = 3;    }
    if ($arg eq  '--togglesni')         { $cfg{'usesni'}    = 3;    }
    if ($arg eq  '--nocert')            { $cfg{'no_cert'}++;        }
    if ($arg eq  '--noignorecase')      { $cfg{'ignorecase'}= 0;    }
    if ($arg eq  '--ignorecase')        { $cfg{'ignorecase'}= 1;    }
    if ($arg eq  '--noignorenoreply')   { $cfg{'ignorenoreply'} = 0;}
    if ($arg eq  '--ignorenoreply')     { $cfg{'ignorenoreply'} = 1;}
    if ($arg eq  '--noexitcode')        { $cfg{'exitcode'}  = 0;    }
    if ($arg eq  '--exitcode')          { $cfg{'exitcode'}  = 1;    } # SEE Note:--exitcode
    if ($arg =~ /^--exitcodenochecks?/) { $cfg{'exitcode_checks'} = 0; } # -"-
    if ($arg =~ /^--exitcodenomedium/)  { $cfg{'exitcode_medium'} = 0; } # -"-
    if ($arg =~ /^--exitcodenoweak/)    { $cfg{'exitcode_weak'} = 0;} # -"-
    if ($arg =~ /^--exitcodenolow/)     { $cfg{'exitcode_low'}  = 0;} # -"-
    if ($arg =~ /^--exitcodenopfs/)     { $cfg{'exitcode_pfs'}  = 0;} # -"-
    if ($arg =~ /^--exitcodenoprot/)    { $cfg{'exitcode_prot'} = 0;} # -"-
    if ($arg =~ /^--exitcodenosizes/)   { $cfg{'exitcode_sizes'}= 0;} # -"-
    if ($arg =~ /^--exitcodenociphers?/){   # shortcut options for following
        $cfg{'exitcode_cipher'} = 0;
        $cfg{'exitcode_medium'} = 0;
        $cfg{'exitcode_weak'}   = 0;
        $cfg{'exitcode_low'}    = 0;
    }
    # some options are for compatibility with other programs
    #   example: -tls1 -tlsv1 --tlsv1 --tls1_1 --tlsv1_1 --tls11 -no_SSL2
    if ($arg =~ /^--?sslv?2$/i)         { $cfg{'SSLv2'}     = 1;    } # allow case insensitive
    if ($arg =~ /^--?sslv?3$/i)         { $cfg{'SSLv3'}     = 1;    } # -"-
    if ($arg =~ /^--?tlsv?1$/i)         { $cfg{'TLSv1'}     = 1;    }
    if ($arg =~ /^--?tlsv?11$/i)        { $cfg{'TLSv11'}    = 1;    }
    if ($arg =~ /^--?tlsv?12$/i)        { $cfg{'TLSv12'}    = 1;    }
    if ($arg =~ /^--?tlsv?13$/i)        { $cfg{'TLSv13'}    = 1;    }
    if ($arg =~ /^--dtlsv?09$/i)        { $cfg{'DTLSv09'}   = 1;    }
    if ($arg =~ /^--dtlsv?10?$/i)       { $cfg{'DTLSv1'}    = 1;    }
    if ($arg =~ /^--dtlsv?11$/i)        { $cfg{'DTLSv11'}   = 1;    }
    if ($arg =~ /^--dtlsv?12$/i)        { $cfg{'DTLSv12'}   = 1;    }
    if ($arg =~ /^--dtlsv?13$/i)        { $cfg{'DTLSv13'}   = 1;    }
    if ($arg =~ /^--nosslv?2$/i)        { $cfg{'SSLv2'}     = 0;    }
    if ($arg =~ /^--nosslv?3$/i)        { $cfg{'SSLv3'}     = 0;    }
    if ($arg =~ /^--notlsv?1$/i)        { $cfg{'TLSv1'}     = 0;    }
    if ($arg =~ /^--notlsv?11$/i)       { $cfg{'TLSv11'}    = 0;    }
    if ($arg =~ /^--notlsv?12$/i)       { $cfg{'TLSv12'}    = 0;    }
    if ($arg =~ /^--notlsv?13$/i)       { $cfg{'TLSv13'}    = 0;    }
    if ($arg =~ /^--nodtlsv?09$/i)      { $cfg{'DTLSv09'}   = 0;    }
    if ($arg =~ /^--nodtlsv?10?$/i)     { $cfg{'DTLSv1'}    = 0;    }
    if ($arg =~ /^--nodtlsv?11$/i)      { $cfg{'DTLSv11'}   = 0;    }
    if ($arg =~ /^--nodtlsv?12$/i)      { $cfg{'DTLSv12'}   = 0;    }
    if ($arg =~ /^--nodtlsv?13$/i)      { $cfg{'DTLSv13'}   = 0;    }
    if ($arg =~ /^--notcp/i)            { $cfg{$_} = 0 foreach (qw(SSLv2 SSLv3 TLSv1 TLSv11 TLSv12 TLSv13)); }
    if ($arg =~ /^--tcp/i)              { $cfg{$_} = 1 foreach (qw(SSLv2 SSLv3 TLSv1 TLSv11 TLSv12 TLSv13)); }
    if ($arg =~ /^--noudp/i)            { $cfg{$_} = 0 foreach (qw(DTLSv09 DTLSv1 DTLSv11 DTLSv12 DTLSv13)); }
    if ($arg =~ /^--udp/i)              { $cfg{$_} = 1 foreach (qw(DTLSv09 DTLSv1 DTLSv11 DTLSv12 DTLSv13)); }
    # options for +cipher
    if ($arg eq   '-cipher')            { $typ = 'CIPHER';          } # openssl
    if ($arg eq  '--cipher')            { $typ = 'CIPHER';          }
    if ($arg eq  '--cipherrange')       { $typ = 'CRANGE';          }
    if ($arg =~ /^--ciphercurves?/)     { $typ = 'CURVES';          }
    if ($arg =~ /^--cipheralpns?/)      { $typ = 'CIPHER_ALPN';     }
    if ($arg =~ /^--ciphernpns?/)       { $typ = 'CIPHER_NPN';      }
    if ($arg eq  '--nociphermd5')       { $cfg{'cipher_md5'}= 0;    }
    if ($arg eq  '--ciphermd5')         { $cfg{'cipher_md5'}= 1;    }
    if ($arg eq  '--nocipherdh')        { $cfg{'cipher_dh'} = 0;    }
    if ($arg eq  '--cipherdh')          { $cfg{'cipher_dh'} = 1;    }
    # our options
    if ($arg eq  '--http')              { $cfg{'usehttp'}++;        }
    if ($arg eq  '--nohttp')            { $cfg{'usehttp'}   = 0;    }
    if ($arg eq  '--norc')              {                           } # simply ignore
    if ($arg eq  '--sslerror')          { $cfg{'ssl_error'} = 1;    }
    if ($arg eq  '--nosslerror')        { $cfg{'ssl_error'} = 0;    }
    if ($arg eq  '--ssllazy')           { $cfg{'ssl_lazy'}  = 1;    }
    if ($arg eq  '--nossllazy')         { $cfg{'ssl_lazy'}  = 0;    }
    if ($arg =~ /^--nullsslv?2$/i)      { $cfg{'nullssl2'}  = 1;    }
    if ($arg =~ /^--sslv?2null$/i)      { $cfg{'nullssl2'}  = 1;    }
    if ($arg eq  '--nodns')             { $cfg{'usedns'}    = 0;    }
    if ($arg eq  '--dns')               { $cfg{'usedns'}    = 1;    }
    if ($arg eq  '--noenabled')         { $cfg{'enabled'}   = 0;    }
    if ($arg eq  '--enabled')           { $cfg{'enabled'}   = 1;    }
    if ($arg eq  '--disabled')          { $cfg{'disabled'}  = 1;    }
    if ($arg eq  '--nodisabled')        { $cfg{'disabled'}  = 0;    }
    if ($arg eq  '--local')             { $cfg{'nolocal'}   = 1;    }
    if ($arg =~ /^--short(?:te?xt)?$/)  { $cfg{'shorttxt'}  = 1;    }
    if ($arg =~ /^--hints?$/)           { $cfg{'out_hint_info'} = 1; $cfg{'out_hint_check'} = 1; }
    if ($arg =~ /^--nohints?$/)         { $cfg{'out_hint_info'} = 0; $cfg{'out_hint_check'} = 0; }
    if ($arg =~ /^--hints?infos?/)      { $cfg{'out_hint_info'} = 1;}
    if ($arg =~ /^--nohints?infos?/)    { $cfg{'out_hint_info'} = 0;}
    if ($arg =~ /^--hints?checks?/)     { $cfg{'out_hint_check'}= 1;}
    if ($arg =~ /^--nohints?checks?/)   { $cfg{'out_hint_check'}= 0;}
    if ($arg =~ /^--hints?cipher/)      { $cfg{'out_hint_cipher'}=1;}
    if ($arg =~ /^--nohints?cipher/)    { $cfg{'out_hint_cipher'}=0;}
    if ($arg eq  '--score')             { $cfg{'out_score'} = 1;    }
    if ($arg eq  '--noscore')           { $cfg{'out_score'} = 0;    }
    if ($arg eq  '--header')            { $cfg{'out_header'}= 1;    }
    if ($arg eq  '--noheader')          { $cfg{'out_header'}= 0;    }
    if ($arg eq  '--tab')               { $text{'separator'}= "\t"; } # TAB character
    if ($arg =~ /^--showhosts?/i)       { $cfg{'showhost'}++;       }
#   if ($arg eq  '--sniname')           { $cfg{'use_sni_name'}  = 1;} # violates historic usage
    if ($arg eq  '--nosniname')         { $cfg{'use_sni_name'}  = 0;}
    if ($arg eq  '--protocol')          { $typ = 'PROTOCOL';        } # ssldiagnose.exe
#   if ($arg eq  '--serverprotocol')    { $typ = 'PROTOCOL';        } # ssldiagnose.exe; # not implemented 'cause we do not support server mode
    if ($arg =~ /^--protoalpns?/)       { $typ = 'PROTO_ALPN';      }
    if ($arg =~ /^--protonpns?/)        { $typ = 'PROTO_NPN';       }
    if ($arg =~ /^--?h(?:ost)?$/)       { $typ = 'HOST';            } # --h already catched above
    if ($arg =~ /^--?p(?:ort)?$/)       { $typ = 'PORT';            }
    if ($arg =~ /^--exe(?:path)?$/)     { $typ = 'EXE';             }
    if ($arg =~ /^--lib(?:path)?$/)     { $typ = 'LIB';             }
    if ($arg eq  '--envlibvar')         { $typ = 'ENV';             }
    if ($arg =~ /^--(?:no|ignore)out(?:put)?$/) { $typ = 'NO_OUT';  }
    if ($arg =~ /^--cfg(.*)$/)          { $typ = 'CFG-' . $1;       } # FIXME: dangerous input
    if ($arg =~ /^--cfgcipher$/)        { $typ = 'CFG-CIPHER';      }
    if ($arg eq  '--call')              { $typ = 'CALL';            }
    if ($arg eq  '--format')            { $typ = 'FORMAT';          }
    if ($arg eq  '--legacy')            { $typ = 'LEGACY';          }
    if ($arg =~ /^--sep(?:arator)?$/)   { $typ = 'SEP';             }
    if ($arg =~ /^--?timeout$/)         { $typ = 'TIMEOUT';         }
    if ($arg =~ /^--nocertte?xt$/)      { $typ = 'CTXT';            }
    if ($arg =~ /^--sniname/i)          { $typ = 'SNINAME';         }
    if ($arg =~ /^--sslerrormax/i)      { $typ = 'SSLERROR_MAX';    }
    if ($arg =~ /^--sslerrortotal/i)    { $typ = 'SSLERROR_TOT';    }
    if ($arg =~ /^--sslerrortotal(?:max)?/i){ $typ = 'SSLERROR_TOT';}
    if ($arg =~ /^--sslerrordelay/i)    { $typ = 'SSLERROR_DLY';    }
    if ($arg =~ /^--sslerrortimeout/i)  { $typ = 'SSLERROR_TOUT';   }
    if ($arg =~ /^--sslerrorperprot/i)  { $typ = 'SSLERROR_PROT';   }
    if ($arg =~ /^--connectdelay/i)     { $typ = 'CONNECT_DLY';     }
    if ($arg eq  '--socketreuse')       { $cfg{'socket_reuse'}  = 1;}
    if ($arg eq  '--nosocketreuse')     { $cfg{'socket_reuse'}  = 0;}
    # options for Net::SSLhello
    if ($arg =~ /^--no(?:dns)?mx/)      { $cfg{'usemx'}     = 0;    }
    if ($arg =~ /^--(?:dns)?mx/)        { $cfg{'usemx'}     = 1;    }
    if ($arg eq  '--sslretry')          { $typ = 'SSLRETRY';        }
    if ($arg eq  '--ssltimeout')        { $typ = 'SSLTOUT';         }
    if ($arg eq  '--sslmaxciphers')     { $typ = 'MAXCIPHER';       }
    if ($arg eq  '--usesignaturealg')   { $cfg{'sslhello'}->{'usesignaturealg'} = 1; }
    if ($arg eq  '--nousesignaturealg') { $cfg{'sslhello'}->{'usesignaturealg'} = 0; }
    if ($arg eq  '--nossluseecc')       { $cfg{'sslhello'}->{'useecc'}   = 0; }
    if ($arg eq  '--ssluseecc')         { $cfg{'sslhello'}->{'useecc'}   = 1; }
    if ($arg eq  '--nossluseecpoint')   { $cfg{'sslhello'}->{'useecpoint'} = 0; }
    if ($arg eq  '--ssluseecpoint')     { $cfg{'sslhello'}->{'useecpoint'} = 1; }
    if ($arg eq  '--nosslusereneg')     { $cfg{'sslhello'}->{'usereneg'} = 0; }
    if ($arg eq  '--sslusereneg')       { $cfg{'sslhello'}->{'usereneg'} = 1; }
    if ($arg eq  '--nossldoublereneg')  { $cfg{'sslhello'}->{'double_reneg'}   = 0; }
    if ($arg eq  '--ssldoublereneg')    { $cfg{'sslhello'}->{'double_reneg'}   = 1; }
    if ($arg eq  '--nodataeqnocipher')  { $cfg{'sslhello'}->{'nodatanocipher'} = 1; }
    if ($arg eq  '--nosslnodatanocipher') { $cfg{'sslhello'}->{'nodatanocipher'} = 0; }
    #!#--------+------------------------+---------------------------+----------
    if ($arg =~ /^--cadepth$/i)         { $typ = 'CADEPTH';         } # some tools use CAdepth
    if ($arg =~ /^--cafile$/i)          { $typ = 'CAFILE';          }
    if ($arg =~ /^--capath$/i)          { $typ = 'CAPATH';          }
    if ($arg =~ /^--stdformat/i)        { $typ = 'STD_FORMAT';      }
    if ($arg =~ /^--winCR/i)            { _set_binmode(":crlf:utf8"); } # historic alias
    # ignored options
    if ($arg =~ /^-connect$/)           {}
    if ($arg eq  '--insecure')          {}
    if ($arg =~ /^--use?r$/)            {}
    if ($arg =~ /^--(?:ciscospeshul|nocolor|nopct|strictpcigrade|UDP)$/)  {} # ssldiagnos.exe
    if ($arg =~ /^--server(cert|certkey|certpass|cipher|protocol|mode)$/) {} #  "
    if ($arg =~ /^-(?:H|r|s|t|url|u|U|x)$/) {}
                # -s HOST   # ssl-cert-check: -s ignored hence HOST parsed as expected
                # -x DAYS   # ssl-cert-check: -x ignored hence DAYS taken as host # FIXME
    #} --------+------------------------+---------------------------+----------

    _y_ARG("option=  $arg") if ($arg =~ /^-/);
    next if ($arg =~ /^-/); # all options handled, remaining are ignored
        # i.e. from sslscan: --no-renegotiation --no-compression ...
        # TODO: means that targets starting with '-' are not possible,
        #       however, such FQDN are illegal

    #{ COMMANDS
    my $p = qr/[._-]/;  # characters used as separators in commands keys
                        # this will always be used as $p? below
    _y_ARG("command? $arg");
    # The following sequence of conditions is important: commands which are an
    # alias for another command are listed first. These aliases should contain
    # the comment  "# alias"  somewhere in the line, so it can be extracted by
    # other tools easily.  The comment  "# alias:"  is used by  --help=alias .
    # the command assigned to $arg should be enclosed in ' (single quote), see
    # o-saft-man.pm' man_alias() for more details.
    # You may read the lines as table with columns like:
    #!#+---------+----------------------+---------------------------+-------------
    #!#           command to check       aliased to                  comment/traditional name
    #!#+---------+----------------------+---------------------------+-------------
    if ($arg =~ /^\+targets?$/)         { $arg = '+host';           } # alias: print host and DNS information
    if ($arg =~ /^\+host$p/)            { $arg = '+host';           } # alias: until indiidual +host-* commands available
    # protocol commands
    if ($arg eq  '+check')              { $check  = 1;              }
    if ($arg eq  '+info')               { $info   = 1;              } # needed 'cause +info and ..
    if ($arg eq  '+quick')              { $quick  = 1;              } # .. +quick convert to list of commands
    if ($arg eq  '+sni')                { $cmdsni = 1;              }
    if ($arg eq  '+http2')              { $arg = '+protocols';      } # alias: HTTP/2.0; TODO: may be changed in future
    if ($arg eq  '+spdy')               { $arg = '+protocols';      } # alias: spdy; TODO: may be changed in future
    if ($arg eq  '+spdy3')              { $arg = '+protocols';      } # alias: SPDY/3.0; TODO: may be changed in future
    if ($arg eq  '+spdy31')             { $arg = '+protocols';      } # alias: SPDY/3.1; TODO: may be changed in future
    if ($arg eq  '+spdy4')              { $arg = '+protocols';      } # alias: SPDY/4.0; TODO: may be changed in future
    if ($arg eq  '+prots')              { $arg = '+protocols';      } # alias:
    if ($arg eq  '+tlsv10')             { $arg = '+tlsv1';          } # alias:
    if ($arg eq  '+dtlsv10')            { $arg = '+dtlsv1';         } # alias:
    # cipher commands
    if ($arg =~ /^\+ciphers?$p?adh/i)   { $arg = '+cipher_adh';     } # alias:
    if ($arg =~ /^\+ciphers?$p?cbc/i)   { $arg = '+cipher_cbc';     } # alias:
    if ($arg =~ /^\+ciphers?$p?des/i)   { $arg = '+cipher_des';     } # alias:
    if ($arg =~ /^\+ciphers?$p?edh/i)   { $arg = '+cipher_edh';     } # alias:
    if ($arg =~ /^\+ciphers?$p?exp/i)   { $arg = '+cipher_exp';     } # alias:
    if ($arg =~ /^\+ciphers?$p?export/i){ $arg = '+cipher_exp';     } # alias:
    if ($arg =~ /^\+ciphers?$p?null/i)  { $arg = '+cipher_null';    } # alias:
    if ($arg =~ /^\+ciphers?$p?weak/i)  { $arg = '+cipher_weak';    } # alias:
    if ($arg =~ /^\+ciphers?$p?order/i) { $arg = '+cipher_order';   } # alias:
    if ($arg =~ /^\+ciphers?$p?strong/i){ $arg = '+cipher_strong';  } # alias:
    if ($arg =~ /^\+ciphers?$p?pfs/i)   { $arg = '+cipher_pfs';     } # alias:
    if ($arg =~ /^\+ciphers?$p?pfsall/i){ $arg = '+cipher_pfsall';  } # alias:
    if ($arg =~ /^\+ciphers?$p?selected/i){$arg= '+cipher_selected';} # alias:
    if ($arg =~ /^\+ciphers$p?openssl/i){ $arg = '+ciphers_local';  } # alias: for backward compatibility
    if ($arg =~ /^\+ciphers$p?local/i)  { $arg = '+ciphers_local';  } # alias:
    if ($arg =~ /^\+all$p?ciphers?/i)   { $arg = '+cipherall';      } # alias:
    if ($arg =~ /^\+raw$p?ciphers?/i)   { $arg = '+cipherraw';      } # alias:
    if ($arg =~ /^\+ciphers?$p?raw/i)   { $arg = '+cipherraw';      } # alias:
    if ($arg =~ /^\+ciphers?$p?prefered?/i){$arg='+cipher_default'; }
    if ($arg =~ /^\+ciphers?$p?defaults?/i){$arg='+cipher_default'; } # alias:
    if ($arg =~ /^\+ciphers?$p?dh/i)    { $arg = '+cipher_dh';      } # alias:
    if ($arg =~ /^\+cipher--?v$/)       { $arg = '+cipher'; $cfg{'v_cipher'}++; } # alias: shortcut for: +cipher --cipher-v
    if ($arg =~ /^\+adh$p?ciphers?/i)   { $arg = '+cipher_adh';     } # alias: backward compatibility < 17.06.17
    if ($arg =~ /^\+cbc$p?ciphers?/i)   { $arg = '+cipher_cbc';     } # alias: backward compatibility < 17.06.17
    if ($arg =~ /^\+des$p?ciphers?/i)   { $arg = '+cipher_des';     } # alias: backward compatibility < 17.06.17
    if ($arg =~ /^\+edh$p?ciphers?/i)   { $arg = '+cipher_edh';     } # alias: backward compatibility < 17.06.17
    if ($arg =~ /^\+exp$p?ciphers?/i)   { $arg = '+cipher_exp';     } # alias: backward compatibility < 17.06.17
    if ($arg =~ /^\+export$p?ciphers?/i){ $arg = '+cipher_exp';     } # alias: backward compatibility < 17.06.17
    if ($arg =~ /^\+null$p?ciphers?/i)  { $arg = '+cipher_null';    } # alias: backward compatibility < 17.06.17
    if ($arg =~ /^\+weak$p?ciphers?/i)  { $arg = '+cipher_weak';    } # alias: backward compatibility < 17.06.17
    if ($arg =~ /^\+order$p?ciphers?/i) { $arg = '+cipher_order';   } # alias: backward compatibility < 17.06.17
    if ($arg =~ /^\+strong$p?ciphers?/i){ $arg = '+cipher_strong';  } # alias: backward compatibility < 17.06.17
    if ($arg =~ /^\+selected$p?ciphers?/i){$arg= '+cipher_selected';} # alias: backward compatibility < 17.06.17
    if ($arg =~ /^\+session$p?ciphers?/i) {$arg= '+cipher_selected';} # alias: backward compatibility < 17.06.17
    if ($arg eq  '+selected')           { $arg = '+cipher_selected';} # alias: backward compatibility < 17.06.17
    if ($arg eq  '+adh')                { $arg = '+cipher_adh';     } # alias:
    if ($arg eq  '+cbc')                { $arg = '+cipher_cbc';     } # alias:
    if ($arg eq  '+des')                { $arg = '+cipher_des';     } # alias:
    if ($arg eq  '+edh')                { $arg = '+cipher_edh';     } # alias:
    if ($arg eq  '+exp')                { $arg = '+cipher_exp';     } # alias:
    if ($arg eq  '+export')             { $arg = '+cipher_exp';     } # alias:
    if ($arg eq  '+null')               { $arg = '+cipher_null';    } # alias:
    if ($arg eq  '+weak')               { $arg = '+cipher_weak';    } # alias:
    # check and info commands
    if ($arg eq  '+owner')              { $arg = '+subject';        } # alias:
    if ($arg eq  '+authority')          { $arg = '+issuer';         } # alias:
    if ($arg eq  '+expire')             { $arg = '+after';          } # alias:
    if ($arg eq  '+extension')          { $arg = '+extensions';     } # alias:
    if ($arg eq  '+sts')                { $arg = '+hsts';           } # alias:
    if ($arg eq  '+sigkey')             { $arg = '+sigdump';        } # alias:
    if ($arg =~ /^\+sigkey$p?algorithm/i){$arg = '+signame';        } # alias:
    if ($arg eq  '+protocol')           { $arg = '+session_protocol'; } # alias:
    if ($arg =~ /^\+selected$p?protocol/i){$arg= '+session_protocol'; } # alias:
    if ($arg =~ /^\+rfc$p?2818$/i)      { $arg = '+rfc_2818_names'; } # alias:
    if ($arg =~ /^\+rfc$p?2818$p?names/i){$arg = '+rfc_2818_names'; } # alias:
    if ($arg =~ /^\+rfc$p?6125$/i)      { $arg = '+rfc_6125_names'; } # alias: # TODO until check is improved (6/2015)
    if ($arg =~ /^\+rfc$p?6125$p?names/i){$arg = '+rfc_6125_names'; } # alias:
    if ($arg =~ /^\+rfc$p?6797$/i)      { $arg = '+hsts';           } # alias:
    if ($arg =~ /^\+rfc$p?7525$/i)      { $arg = '+rfc_7525';       } # alias:
    # do not match +fingerprints  in next line as it may be in .o-saft.pl
    if ($arg =~ /^\+fingerprint$p?(.{2,})$/)          { $arg = '+fingerprint_' . $1;} # alias:
    if ($arg =~ /^\+fingerprint$p?sha$/i)             { $arg = '+fingerprint_sha1'; } # alais:
    if ($arg =~ /^\+subject$p?altnames?/i)            { $arg = '+altname';          } # alias:
    if ($arg =~ /^\+modulus$p?exponent$p?1$/)         { $arg = '+modulus_exp_1';    } # alias:
    if ($arg =~ /^\+modulus$p?exponent$p?65537$/)     { $arg = '+modulus_exp_65537';} # alias:
    if ($arg =~ /^\+modulus$p?exponent$p?size$/)      { $arg = '+modulus_exp_oldssl'; } # alias:
    if ($arg =~ /^\+pubkey$p?enc(?:ryption)?$/)       { $arg = '+pub_encryption'; } # alias:
    if ($arg =~ /^\+public$p?enc(?:ryption)?$/)       { $arg = '+pub_encryption'; } # alias:
    if ($arg =~ /^\+pubkey$p?enc(?:ryption)?$p?known/){ $arg = '+pub_enc_known';  } # alias:
    if ($arg =~ /^\+public$p?enc(?:ryption)?$p?known/){ $arg = '+pub_enc_known';  } # alias:
    if ($arg =~ /^\+ocsp$p?public$p?hash$/)           { $arg = '+ocsp_public_hash'; }
    if ($arg =~ /^\+ocsp$p?subject$p?hash$/)          { $arg = '+ocsp_subject_hash';}
    if ($arg =~ /^\+sig(key)?$p?enc(?:ryption)?$/)    { $arg = '+sig_encryption'; } # alias:
    if ($arg =~ /^\+sig(key)?$p?enc(?:ryption)?_known/){$arg ='+sig_enc_known';   } # alias:
    if ($arg =~ /^\+server$p?(?:temp)?$p?key$/)       { $arg = '+dh_parameter';   } # alias:
    if ($arg =~ /^\+reneg/)             { $arg = '+renegotiation';  } # alias:
    if ($arg =~ /^\+resum/)             { $arg = '+resumption';     } # alias:
    if ($arg =~ /^\+reused?$/i)         { $arg = '+resumption';     } # alias:
    if ($arg =~ /^\+commonName$/i)      { $arg = '+cn';             } # alias:
    if ($arg =~ /^\+cert(?:ificate)?$/i){ $arg = '+pem';            } # alias:
    if ($arg =~ /^\+issuer$p?X509$/i)   { $arg = '+issuer';         } # alias:
    if ($arg =~ /^\+subject$p?X509$/i)  { $arg = '+subject';        } # alias:
    if ($arg =~ /^\+sha2sig(?:nature)?$/){$arg = '+sha2signature';  } # alias:
    if ($arg =~ /^\+sni$p?check$/)      { $arg = '+check_sni';      }
    if ($arg =~ /^\+check$p?sni$/)      { $arg = '+check_sni';      }
    if ($arg =~ /^\+ext$p?aia$/i)       { $arg = '+ext_authority';  } # alias: AIA is a common acronym ...
    if ($arg =~ /^\+vulnerabilit(y|ies)/) {$arg= '+vulns';          } # alias:
    #!#+---------+----------------------+---------------------------+-------------
    #  +---------+----------------------+-----------------------+----------------
    #   command to check     what to do                          what to do next
    #  +---------+----------+-----------------------------------+----------------
    # commands which cannot be combined with others
    if ($arg eq  '+host')   { push(@{$cfg{'do'}}, 'host');                      next; } # special
    if ($arg eq  '+info')   { @{$cfg{'do'}} = (@{$cfg{'cmd-info'}},    'info'); next; }
    if ($arg eq  '+info--v'){ @{$cfg{'do'}} = (@{$cfg{'cmd-info--v'}}, 'info'); next; } # like +info ...
    if ($arg eq  '+quick')  { @{$cfg{'do'}} = (@{$cfg{'cmd-quick'}},  'quick'); next; }
    if ($arg eq  '+check')  { @{$cfg{'do'}} = (@{$cfg{'cmd-check'}},  'check'); next; }
    if ($arg eq  '+vulns')  { @{$cfg{'do'}} = (@{$cfg{'cmd-vulns'}},  'vulns'); next; }
    if ($arg eq '+check_sni'){@{$cfg{'do'}} =  @{$cfg{'cmd-sni--v'}};           next; }
    if ($arg eq '+protocols'){@{$cfg{'do'}} = (@{$cfg{'cmd-prots'}});           next; }
#    if ($arg =~ /^\+next$p?prot(?:ocol)s$/) { @{$cfg{'do'}}= (@{$cfg{'cmd-prots'}}); next; }
    if ($arg eq '+traceSUB'){
        # this command is just documentation, no need to care about other options
        print "# $cfg{'mename'}  list of internal functions:\n";
        my $perlprog = 'sub p($$){printf("%-24s\t%s\n",@_);}
          ($F[0]=~/^#/)&&do{$_=~s/^\s*#\??/-/;p($s,$_)if($s ne "");$s="";};
          ($F[0] eq "sub")&&do{p($s,"")if($s ne "");$s=$F[1];}';
        exec 'perl', '-lane', "$perlprog", $0;
        exit 0;
    }
    if ($arg =~ /^\+(.*)/)  { # all  other commands
        my $val = $1;
        _y_ARG("command= $val");
        next if ($val =~ m/^\+\s*$/);  # ignore empty commands; for CGI mode
        next if ($val =~ m/^\s*$/);    # ignore empty arguments; for CGI mode
        if ($val =~ m/^exec$/i) {      # +exec is special
            $cfg{'exec'} = 1;
            next;
        }
        #_dbx("command= $val");        # convert all +CMD to lower case
        $val = lc($val);               # be greedy to allow +BEAST, +CRIME, etc.
        push(@{$cfg{'done'}->{'arg_cmds'}}, $val);
        if ($val eq 'sizes')    { push(@{$cfg{'do'}}, @{$cfg{'cmd-sizes'}});   next; }
        if ($val eq 'hsts')     { push(@{$cfg{'do'}}, @{$cfg{'cmd-hsts'}});    next; }
        if ($val eq 'http')     { push(@{$cfg{'do'}}, @{$cfg{'cmd-http'}});    next; }
        if ($val eq 'pfs')      { push(@{$cfg{'do'}}, @{$cfg{'cmd-pfs'}});     next; }
        if ($val eq 'sni')      { push(@{$cfg{'do'}}, @{$cfg{'cmd-sni'}});     next; }
        if ($val eq 'ev')       { push(@{$cfg{'do'}}, @{$cfg{'cmd-ev'}});      next; }
        if ($val eq 'bsi')      { push(@{$cfg{'do'}}, @{$cfg{'cmd-bsi'}});     next; }
        if ($val eq 'beast')    { push(@{$cfg{'do'}}, @{$cfg{'cmd-beast'}});   next; }
        if ($val eq 'crime')    { push(@{$cfg{'do'}}, @{$cfg{'cmd-crime'}});   next; }
        if ($val eq 'drown')    { push(@{$cfg{'do'}}, @{$cfg{'cmd-drown'}});   next; }
        if ($val eq 'freak')    { push(@{$cfg{'do'}}, @{$cfg{'cmd-freak'}});   next; }
        if ($val eq 'lucky13')  { push(@{$cfg{'do'}}, @{$cfg{'cmd-lucky13'}}); next; }
        if ($val eq 'robot')    { push(@{$cfg{'do'}}, @{$cfg{'cmd-robot'}});   next; }
        if ($val eq 'sweet32')  { push(@{$cfg{'do'}}, @{$cfg{'cmd-sweet32'}}); next; }
        if ($val =~ /tr$p?02102/){push(@{$cfg{'do'}}, qw(tr_02102+ tr_02102-));next; }
        if ($val =~ /tr$p?03116/){push(@{$cfg{'do'}}, qw(tr_03116+ tr_03116-));next; }
        if (_is_member($val, \@{$cfg{'commands-USR'}}) == 1) {
                                  push(@{$cfg{'do'}}, @{$cfg{"cmd-$val"}});    next; }
        if (_is_member($val, \@{$cfg{'commands-NOTYET'}}) > 0) {
            _warn("044: command not yet implemented '$val' may be ignored");
        }
        if (_is_member($val, \@{$cfg{'commands'}}) == 1) {
            push(@{$cfg{'do'}}, lc($val));      # lc() as only lower case keys are allowed since 14.10.13
        } else {
            _warn("049: command '$val' unknown; command ignored");
        }
        next;
    }
    #} +---------+----------+------------------------------------+----------------

    if ($arg =~ /(?:ciphers|s_client|version)/) {  # handle openssl commands special
        _warn("041: host-like argument '$arg'; treated as command '+$arg'");
        _hint("please use '+$arg' instead");
        push(@{$cfg{'do'}}, $arg);
        next;
    }

    if ($typ eq 'HOST')     {   # host argument is the only one parsed here
        my $host_port = _get_host_port($arg);
        _y_ARG("host=    $host_port");
        _yeast("host: $host_port") if ($cfg{'trace'} > 0);
        if ($host_port =~ m/^\s*$/) {
            _warn("042: invalid host-like argument '$arg'; ignored");
        } else {
            push(@{$cfg{'hosts'}}, $host_port)      if ($host_port !~ m/^\s*$/);
        }
    }

} # while options and arguments

# exit if ($#{$cfg{'do'}} < 0); # no exit here, as we want some --v output

local $\ = "\n";

if ($cfg{'proxyhost'} ne "" && $cfg{'proxyport'} == 0) {
    my $q = "'";
    printusage_exit("$q--proxyhost=$cfg{'proxyhost'}$q requires also '--proxyport=NN'");
}
$verbose = $cfg{'verbose'};
$warning = $cfg{'warning'};
$legacy  = $cfg{'legacy'};
if ((_is_do('cipher')) and ($#{$cfg{'do'}} == 0)) {
    # +cipher does not need DNS and HTTP, may improve perfromance
    # HTTP may also cause errors i.e. for STARTTLS
    $cfg{'usehttp'}     = 0;
    $cfg{'usedns'}      = 0;
}
if (_is_do('ciphers')) {
    # +ciphers command is special:
    #   simulates openssl's ciphers command and accepts -v or -V option
    $cfg{'out_header'}  = 0 if ((grep{/--header/} @argv) <= 0);
    $cfg{'ciphers-v'}   = $cfg{'opt-v'};
    $cfg{'ciphers-V'}   = $cfg{'opt-V'};
    $cfg{'legacy'}      = "openssl" if (($cfg{'opt-v'} + $cfg{'opt-V'}) > 0);
    $text{'separator'}  = " " if ((grep{/--(?:tab|sep(?:arator)?)/} @argv) <= 0); # space if not set
} else {
    # not +ciphers command, then  -V  is for compatibility
    if (! _is_do('list')) {
        $cfg{'out_header'}  = $cfg{'opt-V'} if ($cfg{'out_header'} <= 0);
    }
}
if (_is_do('cipherall')) {
    # +cipherall same as cipherraw with different output format
    push(@{$cfg{'do'}}, 'cipherraw') if (not _is_do('cipherraw'));
}
if (_is_do('list')) {
    # our own command to list ciphers: uses header and TAB as separator
    $cfg{'out_header'}  = 1 if ((grep{/--no.?header/} @argv) <= 0);
    $cfg{'ciphers-v'}   = $cfg{'opt-v'};
    $cfg{'ciphers-V'}   = $cfg{'opt-V'};
    $text{'separator'}  = "\t" if ((grep{/--(?:tab|sep(?:arator)?)/} @argv) <= 0); # tab if not set
}
if (_is_do('pfs'))  { push(@{$cfg{'do'}}, 'cipher_pfsall') if (!_is_do('cipher_pfsall')); }

if (_is_do('version') or ($cfg{'usemx'} > 0)) { $cfg{'need_netdns'} = 1; }
if (_is_do('version') or (_is_do('sts_expired')) > 0) { $cfg{'need_timelocal'} = 1; }

$cfg{'connect_delay'}   =~ s/[^0-9]//g; # simple check for valid values

# set environment
# Note:  openssl  has no option to specify the path to its  configuration
# directoy.  However, some sub command (like req) do have -config option.
# Nevertheless the environment variable is used to specify the path, this
# is independet of the sub command and any platform.
# We set the environment variable only, if  --openssl-cnf  was used which
# then overwrites an already set environment variable.
# This behaviour also honors that  all command line options are  the last
# resort for all configurations.
# As we do not use  req  or  ca  sub commands (11/2015),  this setting is
# just to avoid noicy warnings from openssl.
$ENV{'OPENSSL_CONF'} = $cfg{'openssl_cnf'}  if (defined $cfg{'openssl_cnf'});  ## no critic qw(Variables::RequireLocalizedPunctuationVars
$ENV{'OPENSSL_FIPS'} = $cfg{'openssl_fips'} if (defined $cfg{'openssl_fips'}); ## no critic qw(Variables::RequireLocalizedPunctuationVars

_yeast_args();
_yeast_EXIT("exit=ARGS  - options and arguments done");
_vprintme();

#_init_openssldir();    # called later for performance reasons

usr_pre_exec();

#| call with other libraries
#| -------------------------------------
_y_ARG("exec? $cfg{'exec'}");
# NOTE: this must be the very first action/command
if ($cfg{'exec'} == 0)  {
    # as all shared libraries used by Perl modules are already loaded when
    # this program executes, we need to set PATH and LD_LIBRARY_PATH before
    # being called
    # so we call ourself with proper set environment variables again
    # NOTE: --exe points to the directoy with the openssl executable
    # while --lib points to the directoy with the libraries
    # sometimes, when building new libraries or openssl, the libraries and the
    # executable are located in the same directoy, so we add the directoy given
    # with --lib to the PATH environment variable too, which should not harm
    if (($#{$cmd{'path'}} + $#{$cmd{'libs'}}) > -2) { # any of these is used
        _y_CMD("exec command " . join(" ", @{$cfg{'do'}}));
        #ENV{OPENSSL} no need to set again if already done when called
        my $chr = ($ENV{PATH} =~ m/;/) ? ";" : ":"; # set separator character (lazy)
        my $lib = $ENV{$cmd{envlibvar}};            # save existing LD_LIBRARY_PATH
        local $\ = "\n";
        $ENV{PATH} = join($chr, @{$cmd{'path'}}, $ENV{PATH})  if ($#{$cmd{'path'}} >= 0); ## no critic qw(Variables::RequireLocalizedPunctuationVars)
        $ENV{PATH} = join($chr, @{$cmd{'libs'}}, $ENV{PATH})  if ($#{$cmd{'libs'}} >= 0); ## no critic qw(Variables::RequireLocalizedPunctuationVars)
        $ENV{$cmd{envlibvar}}  = join($chr, @{$cmd{'libs'}})  if ($#{$cmd{'libs'}} >= 0); ## no critic qw(Variables::RequireLocalizedPunctuationVars
        $ENV{$cmd{envlibvar}} .= $chr . $lib if ($lib);
        if ($verbose > 0) {
            _yeast("exec: envlibvar=$cmd{envlibvar}");
            _yeast("exec: $cmd{envlibvar}=" . ($ENV{$cmd{envlibvar}} || "")); # ENV may not exist
            _yeast("exec: PATH=$ENV{PATH}");
        }
        _yeast("exec: $0 +exec " . join(" ", @ARGV));
        _yeast("################################################") if (($cfg{'traceARG'} + $cfg{'traceCMD'}) > 0);
        exec $0, '+exec', @ARGV;
    }
}

#| add openssl-specific path for CAs
#| -------------------------------------
_init_opensslexe();                         # warnings already printed if empty
if (not defined $cfg{'ca_path'}) {          # not passed as option, use default
    $cfg{'ca_path'} = _init_openssldir();   # warnings already printed if empty
}
if (not defined $cfg{'ca_path'} or $cfg{'ca_path'} eq "") {
    # TODO: probably search for a path from our list in $cfg{'ca_paths'}
}

#| openssl and Net::SSLeay is picky about path names
#| -------------------------------------
foreach my $key (qw(ca_file ca_path ca_crl)) {
    next if not defined $cfg{$key};
    _warn("053: option with spaces '$key'='$cfg{$key}'; may cause connection problems")
        if ($cfg{$key} =~ m/\s/);
}

if ($info > 0) {                # +info does not do anything with ciphers
    # main purpose is to avoid missing "*PN" warnings in following _checks_*()
    $cmd{'extciphers'}  = 0;
    $cfg{'usealpn'}     = 0;
    $cfg{'usenpn'}      = 0;
}

_yeast_TIME("inc{");

#| import common and private modules
#| -------------------------------------
_load_modules();

_yeast_TIME("inc}");
_yeast_TIME("mod{");
_y_CMD("check $cfg{'mename'} internals ...");

if (! _is_do('cipherraw'))  {   # +cipherraw does not need these checks

#| check for required module versions
#| -------------------------------------
    # check done after loading our own modules because they may require
    # other common Perl modules too; we may have detailed warnings before
    _check_modules();

#| check for required functionality
#| -------------------------------------
    # more detailed checks on version numbers with proper warning messages
    _check_functions()   if (not _is_do('cipher')); # "if" to improve performance

#| check for proper openssl support
#| -------------------------------------
    _check_openssl();

#| check for supported SSL versions
#| -------------------------------------
    #initialize $cfg{'version'} and all $cfg{ssl}
    _check_SSL_methods() if ((_need_cipher() > 0) or (_need_default() > 0) or _is_do('version'));

} else {
    _check_SSL_methods();   # function is oversized for +cipherraw, but does the work
}; # +cipherraw

_yeast_TIME("mod}");
_yeast_TIME("ini{");

#| set additional defaults if missing
#| -------------------------------------
$cfg{'out_header'}  = 1 if(0 => $verbose); # verbose uses headers
$cfg{'out_header'}  = 1 if(0 => grep{/\+(check|info|quick|cipher)$/} @argv); # see --header
$cfg{'out_header'}  = 0 if(0 => grep{/--no.?header/} @argv);    # command line option overwrites defaults above
if ($cfg{'usehttp'} == 0)   {              # was explizitely set with --no-http 'cause default is 1
    # STS makes no sence without http
    _warn("064: STS $text{'na_http'}") if(0 => (grep{/hsts/} @{$cfg{'do'}})); # check for any hsts*
}
$quick = 1 if ($cfg{'legacy'} eq 'testsslserver');
if ($quick == 1) {
    $cfg{'enabled'} = 1;
    $cfg{'shorttxt'}= 1;
}
$text{'separator'}  = "\t"    if ($cfg{'legacy'} eq "quick");

#| set defaults for Net::SSLinfo
#| -------------------------------------
{
    #$IO::Socket::SSL::DEBUG         = $cfg{'trace'} if ($cfg{'trace'} > 0);
    no warnings qw(once); # avoid: Name "Net::SSLinfo::trace" used only once: possible typo at ...
    if ($cfg{'traceME'} < 1) {
        $Net::SSLinfo::trace        = $cfg{'trace'} if ($cfg{'trace'} > 0);
    }
    $Net::SSLinfo::linux_debug      = $cfg{'linux_debug'};
    $Net::SSLinfo::use_openssl      = $cmd{'extopenssl'};
    $Net::SSLinfo::use_sclient      = $cmd{'extsclient'};
    $Net::SSLinfo::openssl          = $cmd{'openssl'};
    $Net::SSLinfo::use_http         = $cfg{'usehttp'};
    $Net::SSLinfo::use_SNI          = $cfg{'sni_name'};
    $Net::SSLinfo::use_alpn         = $cfg{'usealpn'};
    $Net::SSLinfo::use_npn          = $cfg{'usenpn'};
    $Net::SSLinfo::protos_alpn      = (join(",", @{$cfg{'protos_alpn'}}));
    $Net::SSLinfo::protos_npn       = (join(",", @{$cfg{'protos_npn'}}));
    $Net::SSLinfo::use_extdebug     = $cfg{'use_extdebug'};
    $Net::SSLinfo::use_reconnect    = $cfg{'use_reconnect'};
    $Net::SSLinfo::socket_reuse     = $cfg{'socket_reuse'};
    $Net::SSLinfo::slowly           = $cfg{'slowly'};
    $Net::SSLinfo::sclient_opt      = $cfg{'sclient_opt'};
    $Net::SSLinfo::timeout_sec      = $cfg{'timeout'};
    $Net::SSLinfo::no_cert          = $cfg{'no_cert'};
    $Net::SSLinfo::no_cert_txt      = $cfg{'no_cert_txt'};
    $Net::SSLinfo::ignore_case      = $cfg{'ignorecase'};
    $Net::SSLinfo::ca_crl           = $cfg{'ca_crl'};
    $Net::SSLinfo::ca_file          = $cfg{'ca_file'};
    $Net::SSLinfo::ca_path          = $cfg{'ca_path'};
    $Net::SSLinfo::ca_depth         = $cfg{'ca_depth'};
    $Net::SSLinfo::ignore_handshake = $cfg{'sslerror'}->{'ignore_handshake'};
    $Net::SSLinfo::starttls         = $cfg{'starttls'};
    $Net::SSLinfo::proxyhost        = $cfg{'proxyhost'};
    $Net::SSLinfo::proxyport        = $cfg{'proxyport'};
    $Net::SSLinfo::proxypass        = $cfg{'proxypass'};
    $Net::SSLinfo::proxyuser        = $cfg{'proxyuser'};
    $Net::SSLinfo::file_sclient     = $cfg{'data'}->{'file_sclient'};
    $Net::SSLinfo::file_pem         = $cfg{'data'}->{'file_pem'};
    $Net::SSLinfo::method           = "";
}
if ('cipher' eq join("", @{$cfg{'do'}})) {
    $Net::SSLinfo::use_http         = 0; # if only +cipher given don't use http 'cause it may cause erros
}

#| set defaults for Net::SSLhello
#| -------------------------------------
if (defined $Net::SSLhello::VERSION) {
    no warnings qw(once); # avoid: Name "Net::SSLinfo::trace" used only once: possible typo at ...
    if ($cfg{'traceME'} < 1) {
        $Net::SSLhello::trace       = $cfg{'trace'};
    }
    $Net::SSLhello::traceTIME       = $cfg{'traceTIME'};
    $Net::SSLhello::experimental    = $cfg{'experimental'};
    $Net::SSLhello::usesni          = $cfg{'usesni'};
    $Net::SSLhello::usemx           = $cfg{'usemx'};
    $Net::SSLhello::sni_name        = $cfg{'sni_name'};
    $Net::SSLhello::connect_delay   = $cfg{'connect_delay'};
    $Net::SSLhello::starttls        = (($cfg{'starttls'} eq "") ? 0 : 1);
    $Net::SSLhello::starttlsType    = $cfg{'starttls'};
    $Net::SSLhello::starttlsDelay   = $cfg{'starttls_delay'};
    $Net::SSLhello::slowServerDelay = $cfg{'slow_server_delay'};
    $Net::SSLhello::timeout         = $cfg{'sslhello'}->{'timeout'};
    $Net::SSLhello::retry           = $cfg{'sslhello'}->{'retry'};
    $Net::SSLhello::max_ciphers     = $cfg{'sslhello'}->{'maxciphers'};
    $Net::SSLhello::use_signature_alg = $cfg{'sslhello'}->{'usesignaturealg'};
    $Net::SSLhello::usereneg        = $cfg{'sslhello'}->{'usereneg'};
    $Net::SSLhello::useecc          = $cfg{'sslhello'}->{'useecc'};
    $Net::SSLhello::useecpoint      = $cfg{'sslhello'}->{'useecpoint'};
    $Net::SSLhello::double_reneg    = $cfg{'sslhello'}->{'double_reneg'};
    $Net::SSLhello::noDataEqNoCipher= $cfg{'sslhello'}->{'nodatanocipher'};
    $Net::SSLhello::proxyhost       = $cfg{'proxyhost'};
    $Net::SSLhello::proxyport       = $cfg{'proxyport'};
    $Net::SSLhello::cipherrange     = $cfg{'cipherrange'};  # not really necessary, see below
    $Net::SSLhello::ciphercurves    = (join(":", @{$cfg{'ciphercurves'}}));
    $Net::SSLhello::protos_alpn     = (join(",", @{$cfg{'protos_alpn'}}));
    $Net::SSLhello::protos_npn      = (join(",", @{$cfg{'protos_npn'}}));
    # TODO: need to unify variables
    @Net::SSLhello::starttlsPhaseArray  = @{$cfg{'starttls_phase'}};
    # add 'starttls_error' array elements according Net::SSLhello's internal
    # representation
    push(@Net::SSLhello::starttlsPhaseArray, @{$cfg{'starttls_error'}}[1..3]);
}
$cfg{'trace'} = 0 if ($cfg{'traceME'} < 0);

if ($cfg{'shorttxt'} > 0) {     # reconfigure texts
    foreach my $key (keys %data)   { $data{$key}  ->{'txt'} = $shorttexts{$key}; }
    foreach my $key (keys %checks) { $checks{$key}->{'txt'} = $shorttexts{$key}; }
}

_yeast_TIME("ini}");

#| first all commands which do not make a connection
#| -------------------------------------
_y_CMD("no connection commands ...");
if (_is_do('list'))       { printciphers(); exit 0; }
if (_is_do('ciphers'))    { printciphers(); exit 0; }
if (_is_do('version'))    { printversion(); exit 0; }
if (_is_do('libversion')) { printopenssl(); exit 0; }
if (_is_do('quit'))       { printquit();    exit 0; } # internal test command

if (($cfg{'trace'} + $cfg{'verbose'}) >  0) {   # +info command is special with --v
    @{$cfg{'do'}} = @{$cfg{'cmd-info--v'}} if (@{$cfg{'do'}} eq @{$cfg{'cmd-info'}});
}
_yeast_init();  # call in printquit() also!

if ($#{$cfg{'do'}} < 0) {
    _yeast_exit();
    printusage_exit("no command given");
}

usr_pre_cipher();

#| get list of ciphers available for tests
#| -------------------------------------
# TODO: move this code-block up behind call of _check_SSL_methods();
#       needs exhausting tests with previous non-connecting commands
#       needs also proper tests what Net::SSLinfo::cipher_* returns,
#       see _get_ciphers_list()
_yeast_TIME("get{");
if ((_need_cipher() > 0) or (_need_default() > 0)) {
    _y_CMD("  get cipher list ...");
    @{$cfg{'ciphers'}} = _get_ciphers_list();

} # _need_cipher or _need_default
_yeast_TIME("get}");

_yeast_EXIT("exit=MAIN  - start");
_yeast_ciphers();
usr_pre_main();

#| main: do the work for all targets
#| -------------------------------------

# defense, user-friendly programming
  # could do these checks earlier (after setting defaults), but we want
  # to keep all checks together for better maintenace
printusage_exit("no target hosts given") if ($#{$cfg{'hosts'}} < 0); # does not make any sense
if (_is_do('cipher')) {
    if ($#{$cfg{'done'}->{'arg_cmds'}} > 0) {
        printusage_exit("additional commands in conjunction with '+cipher' are not supported; '+" . join(" +", @{$cfg{'done'}->{'arg_cmds'}}) ."'");
    }
}
if (($info > 0) and ($#{$cfg{'done'}->{'arg_cmds'}} >= 0)) {
    # +info does not allow additional commands
    # see printchecks() call below
    _warn("047: additional commands in conjunction with '+info' are not supported; '+" . join(" +", @{$cfg{'done'}->{'arg_cmds'}}) . "' ignored");
}
if (($check > 0) and ($#{$cfg{'done'}->{'arg_cmds'}} >= 0)) {
    # +check does not allow additional commands of type "info"
    foreach my $key (@{$cfg{'done'}->{'arg_cmds'}}) {
        if (_is_member( $key, \@{$cfg{'cmd-info'}}) > 0) {
            _warn("048: additional commands in conjunction with '+check' are not supported; +'$key' ignored");
        }
    }
}

#| main: perform commands for all hosts
#| -------------------------------------

usr_pre_host();

my $fail = 0;
# check if output disabled for given/used commands, SEE Note:ignore-out
foreach my $cmd (@{$cfg{'ignore-out'}}) {
    $fail++ if (_is_do($cmd) > 0);
}
if ($fail > 0) {
    _warn("066: $fail data and check outputs are disbaled due to use of '--no-out':");
    if ($cfg{'verbose'} >  0) {
        _warn("067:  disabled:  +" . join(" +", @{$cfg{'ignore-out'}}));
        _warn("068:  given:  +" . join(" +", @{$cfg{'do'}}));
    } else {
        _hint("use  '--v'  for more information");
    }
    _hint("do not use '--ignore-out=*' or '--no-out=*' options");
        # It's not simple to identify the given command, as $cfg{'do'} may
        # contain a list of commands. So the hint is a bit vage.
        # _dbx "@{$cfg{'done'}->{'arg_cmds'}}"
} else {
    # print warnings and hints if necessary
    foreach my $cmd (@{$cfg{'do'}}) {
        if (_is_member($cmd, \@{$cfg{'commands-HINT'}}) > 0) {
            _hint("+$cmd : please see  '$me --help=CHECKS'  for more information");
        }
    }
}

_y_CMD("hosts ...");
_yeast_TIME("hosts{");

# run the appropriate SSL tests for each host (ugly code down here):
$port = ($cfg{'port'}||"");     # defensive programming ..
foreach my $host (@{$cfg{'hosts'}}) {  # loop hosts
    ($host, $port)  = split(/:([^:\]]+)$/, $host); # split right most : (remember IPv6)
    $port = $cfg{'port'} if ($port =~ m/^\s*$/);
    $cfg{'port'}    = $port;
    $cfg{'host'}    = $host;
    _yeast_EXIT("exit=HOST0 - perform host start");
    _y_CMD("host " . ($host||"") . ":$port {");
    _trace(" host: $host {\n");
    _resetchecks();
    printheader(_get_text('out_target', "$host:$port"), "");

    _yeast_TIME("DNS{");

    # prepare DNS stuff
    #  gethostbyname() and gethostbyaddr() set $? on error, needs to be reset!
    my $rhost = "";
    $fail = "";
    if ($cfg{'proxyhost'} ne "") {
        # if a proxy is used, DNS might not work at all, or be done by the
        # proxy (which even may return other results than the local client)
        # so we set corresponding values to a warning
        $fail = _get_text('disabled', "--proxyhost=$cfg{'proxyhost'}");
        $cfg{'rhost'}   = $fail;
        $cfg{'DNS'}     = $fail;
        $cfg{'IP'}      = $fail;
        $cfg{'ip'}      = $fail;
    } else {
        $fail  = '<<gethostbyaddr() failed>>';
        $cfg{'ip'}      = gethostbyname($host); # primary IP as identified by given hostname
        if (not defined $cfg{'ip'}) {
            _warn("201: Can't get IP for host '$host'; host ignored");
            _y_CMD("host}");
            next; # otherwise all following fails
        }
        # gethostbyaddr() is strange: returns $?==0 but an error message in $!
        # hence just checking $? is not reliable, we do it additionally.
        # If gethostbyaddr()  fails we use Perl's  `or'  to assign our default
        # text.  This may happen when there're problems with the local name
        # resolution.
        # When gethostbyaddr() fails, the connection to the target most likely
        # fails also, which produces more Perl warnings later.
        _y_CMD("test IP ...");
        $cfg{'IP'}          = join(".", unpack("W4", $cfg{'ip'}));
        if ($cfg{'usedns'} == 1) {  # following settings only with --dns
           _yeast_TIME("use DNS{");
           local $? = 0; local $! = undef;
           ($cfg{'rhost'}   = gethostbyaddr($cfg{'ip'}, AF_INET)) or $cfg{'rhost'} = $fail;
            $cfg{'rhost'}   = $fail if ($? != 0);
            _y_CMD("test DNS (disable with --no-dns) ...");
            my ($fqdn, $aliases, $addrtype, $length, @ips) = gethostbyname($host);
            my $i = 0;
            foreach my $ip (@ips) {
                local $? = 0; local $! = undef;
               ($rhost  = gethostbyaddr($ip, AF_INET)) or $rhost = $fail;
                $rhost  = $fail if ($? != 0);
                $cfg{'DNS'} .= join(".", unpack("W4", $cfg{'ip'})) . " " . $rhost . "; ";
                #dbx# printf "[%s] = %s\t%s\n", $i, join(".",unpack("W4",$ip)), $rhost;
            }
            _warn("202: Can't do DNS reverse lookup: for $host: $fail; ignored") if ($cfg{'rhost'} =~ m/gethostbyaddr/);
           _yeast_TIME("use DNS}");
        }
    }
    # print DNS stuff
    if (_is_do('host') or (($info + $check + $cmdsni) > 0)) {
        _y_CMD("+info || +check || +sni*");
        if ($legacy =~ /(full|compact|simple)/) {
            printruler();
            print_line($legacy, $host, $port, 'host_name', $text{'host_name'}, $host);
            print_line($legacy, $host, $port, 'host_IP',   $text{'host_IP'}, $cfg{'IP'});
            if ($cfg{'usedns'} == 1) {
                print_line($legacy, $host, $port, 'host_rhost', $text{'host_rhost'}, $cfg{'rhost'});
                print_line($legacy, $host, $port, 'host_DNS',   $text{'host_DNS'},   $cfg{'DNS'});
            }
            printruler();
        }
    }

    _yeast_TIME("DNS}");

    # Quick check if the target is available
    _yeast_TIME("can_connect{");# SEE Note:Connection test
    if (not _can_connect($host, $port, $cfg{'sni_name'}, $cfg{'timeout'}, 1)) {
        next if ($cfg{'sslerror'}->{'ignore_no_conn'} <= 0);
    }
    if (not _can_connect($host, 80   , $cfg{'sni_name'}, $cfg{'timeout'}, 0)) {
        $cfg{'usehttp'} = 0;
        $Net::SSLinfo::use_http = $cfg{'usehttp'}; # FIXME: wrong if there're multiple targets given
        _warn("325: HTTP disabled, using --no-http");
        next;
    }
    _yeast_TIME("can_connect}");

    if (_is_do('cipherraw')) {
        _yeast_TIME("cipherraw{");
        _y_CMD("+cipherraw");
        Net::SSLhello::printParameters() if ($cfg{'trace'} > 1);
        _warn("209: No SSL versions for +cipherraw available") if ($#{$cfg{'version'}} < 0);
            # above warning is most likely a programming error herein
        my $total   = 0;
        my $enabled = 0;
        my $_printtitle = 0;    # count title lines; 0 = no ciphers checked
        my @results = ();       # new cipher list for every host
        foreach my $ssl (@{$cfg{'version'}}) {
            $_printtitle++;
            next if ($cfg{$ssl} == 0);
            if ($Net::SSLhello::usesni >= 1) { # always test first without SNI
                # using $Net::SSLhello::usesni instead of $cfg{'usesni'} (even
                # they should be the same) because Net::SSLhello functions are
                # called
                if ($ssl =~ m/^SSLv/) {
                    # SSLv2 has no SNI; SSLv3 has originally no SNI
                    _warn_nosni("409:", $ssl, $Net::SSLhello::usesni);
                    next;
                }
            }
            my @all = _get_ciphers_range($ssl, $cfg{'cipherrange'});
            my @accepted = ();                          # accepted ciphers
            $total += scalar @all;
            printtitle($legacy, $ssl, $host, $port);
            if (not _is_do('cipherall')) {
                _v_print("cipher range: $cfg{'cipherrange'}");
                _v_print sprintf("total number of ciphers to check: %4d", scalar(@all));
            }
            @accepted = Net::SSLhello::checkSSLciphers($host, $port, $ssl, @all);
            if (not _is_do('cipherall')) {
                _v_print(sprintf("total number of accepted ciphers: %4d",
                             (scalar(@accepted) - (scalar(@accepted) >= 2 && ($accepted[0] eq $accepted[1]))) ));
                # correct total number if first 2 ciphers are identical
                # (this indicates cipher order by the server)
                # delete 1 when the first 2 ciphers are identical (this indicates an order by the server)
            }
            if (_is_do('cipherall')) {
                $enabled += printcipherall($legacy, $ssl, $host, $port,
                    ($legacy eq "sslscan")?($_printtitle):0, @accepted);
                print_check($legacy, $host, $port, 'cnt_totals', scalar(@all)) if ($cfg{'verbose'} > 0);
                next if (scalar @accepted < 1); # defensive programming ..
                # prepare for printing ...
                my $cipher = get_cipher_suitename($accepted[0]);
                # SEE Note:+cipherall
                $prot{$ssl}->{'cipher_strong'}  = $cipher;
                $prot{$ssl}->{'default'}        = $cipher;
                my $last_a  = "";    # avoid duplicates
                foreach my $key (@accepted) {
                    # each entry looks like:  TLSv12  AES128-SHA256  yes
                    next if ($last_a eq $key);
                    push(@results, [$ssl, get_cipher_suitename($key), "yes"]);
                    $last_a = $key;
                }
            } else {
                Net::SSLhello::printCipherStringArray('compact', $host, $port, $ssl, $Net::SSLhello::usesni, @accepted);
            }
        } # $ssl
        if ($_printtitle > 0) {
            # SEE Note:+cipherall
            checkciphers($host, $port, @results);   # necessary to compute 'out_summary'
            printciphersummary($legacy, $host, $port, $total);
        }
        _yeast_TIME("cipherraw}");
        next; # FIXME: SEE Note:+cipherall
    } # cipherraw

    if (_is_do('fallback_protocol')) {
        _y_CMD("protocol fallback support ...");
        # following similar to ciphers_scan_prot();
        my ($version, $supported, $dh);
        if (0 == $cmd{'extciphers'}) {
            ($version, $supported)      = _usesocket( '', $host, $port, '');
        } else { # force openssl
            ($version, $supported, $dh) = _useopenssl('', $host, $port, '');
        }
        $prot{'fallback'}->{val} = $version;
        _trace("fallback: $version $supported");
    }

    if ((_need_default() > 0) or ($check > 0)) {
        # SEE Note:+cipherall
        _yeast_TIME("need_default{");
        $cfg{'done'}->{'ssl_failed'} = 0;   # SEE Note:--ssl-error
        _y_CMD("get default ...");
        foreach my $ssl (@{$cfg{'version'}}) {  # all requested protocol versions
            next if (not defined $prot{$ssl}->{opt});
            my $anf = time();
            # no need to check for "valid" $ssl (like DTLSfamily), done by _get_default()
            $prot{$ssl}->{'cipher_strong'}  = _get_default($ssl, $host, $port, 'strong');
            $prot{$ssl}->{'cipher_weak'}    = _get_default($ssl, $host, $port, 'weak');
            $prot{$ssl}->{'default'}        = _get_default($ssl, $host, $port, 'default');
            # FIXME: there are 3 connections above, but only one is counted
            last if (_is_ssl_error($anf, time(), "$ssl: abort getting prefered cipher") > 0);
            my $cipher  = $prot{$ssl}->{'cipher_strong'};
            $prot{$ssl}->{'cipher_pfs'}     = $cipher if ("" eq _ispfs($ssl, $cipher));
            ##if (_is_do('cipher_selected') and ($#{$cfg{'do'}} == 0)) {
            ##    # +cipher_selected command given, but no other commands; ready
            ##    print_cipherprefered($legacy, $ssl, $host, $port); # need to check if $ssl available first
            ##    next HOSTS; # TODO: foreach-loop for hosts misses label
            ##}
        }
        checkprefered($host, $port);
        _yeast_TIME("need_default}");
    }

    if (_is_do('cipher_default') and ($#{$cfg{'do'}} == 0)) {
        # don't print if not a single command, because +check or +cipher do it
        # in printptotocols() anyway
        printcipherprefered($legacy, $host, $port);
        goto CLOSE_SSL; # next HOSTS
    }

    if (_need_cipher() > 0) {
        _yeast_TIME("need_cipher{");
        _y_CMD("  need_cipher ...");
        _y_CMD("  use socket ...")  if (0 == $cmd{'extciphers'});
        _y_CMD("  use openssl ...") if (1 == $cmd{'extciphers'});
        @cipher_results = ();   # new list for every host
        $checks{'cnt_totals'}->{val} = 0;
        #dbx# _dbx "ciphers:", @{$cfg{'ciphers'}};
        ciphers_scan($host, $port);
        $checks{'cnt_totals'}->{val} = scalar @cipher_results;
        #dbx @cipher_results = (); # simulate "no ciphers found"
        checkciphers($host, $port, @cipher_results); # necessary to compute 'out_summary'
        _yeast_TIME("need_cipher}");
     }

    # check ciphers manually (required for +check also)
    if (_is_do('cipher') or $check > 0) {
        _yeast_TIME("cipher{");
        _y_CMD("+cipher");
        _trace(" ciphers: @{$cfg{'ciphers'}}");
        # TODO: for legacy==testsslserver we need a summary line like:
        #      Supported versions: SSLv3 TLSv1.0
        my $_printtitle = 0;    # count title lines; 0 = no ciphers checked
        foreach my $ssl (@{$cfg{'version'}}) {
            $_printtitle++;
            if (($legacy ne "sslscan") or ($_printtitle <= 1)) {
                # format of sslscan not yet supported correctly
                if (($cfg{'out_header'} > 0) or (scalar @{$cfg{'version'}}) > 1) {
                    # need a header when more than one protocol is checked
                    printtitle($legacy, $ssl, $host, $port);
                }
            }
            # TODO: need to simplify above conditions
            printciphercheck($legacy, $ssl, $host, $port,
                ($legacy eq "sslscan")?($_printtitle):0, @cipher_results);
        }
        if ($legacy eq 'sslscan') {
            my $ssl = ${$cfg{'version'}}[4];
            print_cipherprefered($legacy, $ssl, $host, $port);
            # TODO: there is only one $data{'cipher_selected'}
            #foreach my $ssl (@{$cfg{'version'}}) {
            #    print_cipherprefered($legacy, $ssl, $host, $port);
            #}
        }
        if ($_printtitle > 0) { # if we checked for ciphers
            # SEE Note:+cipherall
            printciphersummary($legacy, $host, $port, scalar @cipher_results);
        }
        _yeast_TIME("cipher}");
    } # cipher

    goto CLOSE_SSL if ((_is_do('cipher') > 0) and ($quick == 0));

    usr_pre_info();
    _yeast_TIME("SNI{");

# FIXME: some servers do not respond for following
#        reason seams to be SSLv2 or SSLv3 without SNI
# FIXME: cannot use:    if ($cfg{usesni} > 0) 
#        need to review code first for %data0 usage
    # 21nov17: following temporarily disabled due to performance reasons
    # _get_data0($host, $port);

    _yeast_TIME("SNI}");
    usr_pre_open();

    # TODO dirty hack, check with dh256.tlsfun.de
    # checking for DH parameters does not need a default connection
    if (_is_do('cipher_dh')) {
        _yeast_TIME("cipher-dh{");
        printciphers_dh($legacy, $host, $port);
        _yeast_TIME("cipher-dh}");
        goto CLOSE_SSL;
    }

    # SEE Note:Connection test
    if ($cfg{'sslerror'}->{'ignore_no_conn'} <= 0) {
        # use Net::SSLinfo::do_ssl_open() instead of IO::Socket::INET->new()
        # to check the connection (hostname and port)
        # NOTE: the previous test (see can_connect above) should be sufficient
        _yeast_TIME("connection test{");
        _y_CMD("test connection  (disable with  --ignore-no-conn) ...");
        if (not defined Net::SSLinfo::do_ssl_open(
                            $host, $port,
                            (join(" ", @{$cfg{'version'}})),
                             join(" ", @{$cfg{'ciphers'}}))
           ) {
            my @errtxt = Net::SSLinfo::errors($host, $port);
            if ($#errtxt > 0) {
                _v_print(join("\n".STR_ERROR, @errtxt));
                _warn("205: Can't make a connection to $host:$port; target ignored");
                _hint("--v  will show more information");
                _hint("--socket-reuse  may help in some cases");
                _hint("--ignore-no-conn can be used to disable this check");
                _hint("do not use --no-ignore-handshake") if ($cfg{'sslerror'}->{'ignore_handshake'} <= 0);
                _yeast_TIME("  connection test} failed");
                goto CLOSE_SSL;
            }
        }
        _yeast_TIME("  connection open.");
        my @errtxt = Net::SSLinfo::errors($host, $port);
        if ((grep{/\*\*ERROR/} @errtxt) > 0) {
            _warn("207: Errors occoured when using '$cmd{'openssl'}', some results may be wrong; errors ignored");
            _hint("--v  will show more information");
            # do not print @errtxt because of multiple lines not in standard format
        }
        _yeast_TIME("connection test}");
    }

    usr_pre_cmds();
    _yeast_TIME("prepare{");

    if (_is_do('dump')) {
        _y_CMD("+dump");
        if ($cfg{'trace'} > 1) {   # requires: --v --trace --trace
            _trace(' ############################################################ %SSLinfo');
            print Net::SSLinfo::datadump();
        }
        printdump($legacy, $host, $port);
    }

    usr_pre_data();

    # following sequence important!
    # if conditions are just to improve performance
    _y_CMD("get checks ...");
    if (_need_checkalpn() > 0) {
        _y_CMD("  need_pn ...");
        checkalpn( $host, $port);   _yeast_TIME("  checkalpn.");
    }
        checkdates($host, $port);   _yeast_TIME("  checkdates.");
    if (_need_checkhttp() > 0) {
        checkhttp( $host, $port);   _yeast_TIME("  checkhttp.");
    }
        checksni(  $host, $port);   _yeast_TIME("  checksni.");
        checksizes($host, $port);   _yeast_TIME("  checksizes.");
    if ($info == 0) {   # not for +info
        checkdv(   $host, $port);   _yeast_TIME("  checkdv.");
    }
    if (_need_checkprot() > 0) {
        checkprot( $host, $port);   _yeast_TIME("  checkprot.");
    }
    if (_need_checkdest() > 0) {
        checkdest( $host, $port);   _yeast_TIME("  checkdest.");
    }
    if (_need_checkbleed() > 0) {
        _y_CMD("  need_checkbleed ...");
        checkbleed($host, $port);   _yeast_TIME("  checkbleed.");
    }
    if (_need_checkssl() > 0) {
        _y_CMD("  need_checkssl ...");
        checkssl(  $host, $port);   _yeast_TIME("  checkssl.");
     }

    _yeast_TIME("prepare}");
    usr_pre_print();

    if ($check > 0) {
        _y_CMD("+check");
        _warn("208: No openssl, some checks are missing") if (($^O =~ m/MSWin32/) and ($cmd{'extopenssl'} == 0));
    }

    # for debugging only
    if (_is_do('s_client')) {
        _y_CMD("+s_client"); print "#{\n", Net::SSLinfo::s_client($host, $port), "\n#}";
    }
    _y_CMD("do=".join(" ",@{$cfg{'do'}}));

    # print all required data and checks
    # NOTE: if key (aka given command) exists in %checks and %data it will be printed twice
    _yeast_TIME("info{");
    printdata(  $legacy, $host, $port) if ($check == 0); # not for +check
    _yeast_TIME("info}");
    _yeast_TIME("checks{");
    printchecks($legacy, $host, $port) if ($info  == 0); # not for +info
    _yeast_TIME("checks}");

    if ($cfg{'out_score'} > 0) { # no output for +info also
        _yeast_TIME("score{");
        _y_CMD("scores");
        printscores($legacy, $host, $port);
        _yeast_TIME("score}");
    }

    CLOSE_SSL:
    _y_CMD("host " . ($host||"") . ":$port }");
    {
      no warnings qw(once);
      if (defined $Net::SSLinfo::socket) { # check to avoid: WARNING undefined Net::SSLinfo::socket
        Net::SSLinfo::do_ssl_close($host, $port);
      }
    }
    _trace(" host: $host }\n");
    $cfg{'done'}->{'hosts'}++;

    usr_pre_next();
    _yeast_EXIT("exit=HOST1 - perform host end");

} # foreach host

_yeast_TIME("hosts}");

usr_pre_exit();
_yeast_exit();
_yeast_EXIT("exit=MAIN  - end");    # for symetric reason, rather useless here

if ($cfg{'exitcode'} == 0) {
    exit 0;
} else {
    exit check_exitcode();
}
exit 2; # main; code never reached

__END__
__DATA__
public user documentation, please see  OSaft/Doc/*.txt  and  OSaft/Doc/Data.pm 

=pod

=encoding utf8

=head1 Annotations, Internal Notes

The annotations here describe  behaviours, observations, and alike,  which
lead to special program logic. The intention is to have one central place,
where to do the documentation.
Up to now --2018-- this is an internal documentaion only.  It is planed to
be available for the user too, i.e. with --help .

It is written in POD format, because some tools analyzing the code want to
"see" comments and documentation. We feed them. For more information about
that, please see "woodoo" in o-saft-man.pm .
Note that only POD's =head2 syntax is used. It marks a single annotation.
The reference to such an annotation uses  SEE  in the code.
All following text is supposed to be read by humans!

The term  Perl  is used when the programming language in general is meant.
The term  perl  is used when the program perl (or perl.exe) is meant.
The term  Perl::Critic  is used when the functionality of the Perl::Critic
module, or any program using it, is meant.
The term   perlcritic   is used when the program perlcritic is meant.


=head2 Perl:import include

Perl's recommend way to import modules is the `use' or `require' statement
Both methods have the disadvantage that this scripts fails  if a requested
module is missing.  The script fails immediately at startup if modules are
loaded with `use', or at runtime id loaded with `require'.

One goal is to be able to run on  ancient or incomplete configured systems
too. Hence we try to load all modules with our own function  _load_file(),
which uses `require' to load the module at runtime. This way it's possible
to selectively disable just some functionality if loading of a module fails
for various reasons (i.e. wrong version).

Perl's `use autouse' is also not possible, as to much functions need to be
declared for that pragma then.
Unfortunately some common Perl modules resist to be loaded with `require'.
They are still imported using  use  .


=head2 Perl:BEGIN

Loading `require'd  files and modules  as well as parsing the command line
in Perl's  BEGIN section  increases performance and lowers the memory foot
print for some commands (see o-saft-man.pm also).
Unfortunately Perl's BEGIN has following limits and restrictions:

  - constants can be defined before and used herein
  - sub can be defined herein and used later
  - variables can not be defined herein and used later
  - some file handles (like <DATA>) are not yet available
  - strict sequence of definitions and usage (even for variables in subs)

Perl subs used in the  BEGIN section must be defined there also, or before
the BEGIN section (which is a crazy behaviour of Perl).
To make the program work as needed,  these limitations  forces to use some
dirty code hacks and split the flow of processing into  different parts of
the source.


=head2 Perl:binmode()

Perl uses various layers for I/O operations. It's called  I/O layers (also
known as discipline). Layers to be used are defined globaly with binmode()
or individually in each open() call. All the glory details can be found in
Perl's documentation (man or perldoc) for: PerlIO, binmode, open.

The tool here roughly destingushes two types of I/O:

    1. writeing texts to the user using STDOUT and STDERR channels
       note that it never reads, except from command line, hence no STDIN
    2. reading and writing to network sockets, which is done underneath

We assume that the  I/O socket (2. above)  is handled properly by the used
modules. This leaves STDOUT and STDERR (1. above) to be set properly.

As most --nearly all-- data on STDOUT and STDERR is supposed to be read by
humans. Only these channels are handled explicitely. The idea is, that all
texts consist of printable characters only, probably in various languages.
Hence UTF-8 is used as default characters set. The channels are configured
to expect UTF-8 characters.
Perl destingushes between ':utf8' and ':encoding(UTF-8)' layer,  where the
':utf8' does not check for valid encodings. ':utf8' is sufficient here, as
we only want to ensure UTF-8 on output.
The I/O layers need to be set in the main script only, all modules inherit
the settings from there.

Note that we use STDOUT and STDERR  and not the pseudo layer ':std' or the
-S flag/option, because they also contain STDIN.


=head2 Perl:map()

To replace data in each item of an arrays,  Perl provides various methods,
examples:

    @arr = map {$_ =~ s/old/new/g; $_; } @arr;  # 0. very bad
    @arr = map {      s/old/new/g; $_; } @arr;  # 1. bad
           map {      s/old/new/g;     } @arr;  # 2. better
                      s/old/new/     for @arr;  # 3. best

we prefer the perlish one (3. above).  Because it does not copy the array,
it is the most performant solution also.
Unfortunatelly Perl::Critic complains about postfix controls with
ControlStructures::ProhibitPostfixControls  which seems to be misleading.
If there are multiple substitutions to be done, it is better to use a loop
like (which then keep Perl::Critic happy too):

    while (@arr) {
        s/old/new/;
        s/alt/neu/;
    }


=head2 Perl:warn _warn

I.g. Perl's warn() is not used, but our private _warn(). Using _warn() can
supressed messages with the  --no-warning  option.  However, some warnings
should never be supressed, hence warn() is used in rare cases.
Each warning should have a unique number, SEE Perl:Message Numbers .
See also  CONCEPTS  (if it exists in our help texts).


=head2 Perl:Message Numbers

Each warning has a unique number. The numbers are grouped as follows:

    0xx     startup check, options, arguments
    1xx     check (runtime) functionality
    2xx     loop hosts
    3xx     connect functions
    4xx     cipher check functions
    5xx     inernal check functions
    6xx     check functions
    8xx     print functions

Check for used numbers with:
    egrep '(die|_warn| warn )' o-saft.pl | sed -e 's/^ *//' | sort


=head2 Note:Documentation

All documentation is in plain text format. All documentation available for
users is located in its own file. The documentation texts are designed for
human radability and simple editing. 

For details on documentation texts from files, see  ./OSaft/Doc/Data.pm .

Since VERSION 18.01.18
All public user documentation is now in plain text files which use charset
UTF-8, see  ./OSaft/Doc/*.txt . Previous files ./OSaft/Doc/*.pm  have been
replaced by  ./OSaft/Doc/Data.pm  and these plain text files.
Reading plain text from external files instead of  Perl's DATA also avoids
sophisticated computation of the correct file and DATA handle, for example
when  ./OSaft/Doc/*.pm  is imported in  Perl's BEGIN section,  please also
SEE Perl:BEGIN  above.

Since VERSION 17.07.17
All documentation from variables, i.e.  %man_text, moved to separate files 
in  ./OSaft/Doc/*. This simplified editing texts as they are  simple ASCII
format in the  __DATA__ section of each file. The overhead compared to the
%man_text  variable is just the Perl module file with its  POD texts.  The
disadvantage is, that it's more complicated to import the data in a stand-
alone script, see  contrib/gen_standalone.sh .

Since VERSION 17.06.17
All user documentation is now in  o-saft-man.pl, which uses a mix of texts
defined in Perl variables,  i.e. %man_text.  The public user documentation
is defined in the  __DATA__  section (mainly all the documentation).

Until VERSION 14.11.12
Initilly the documentation was written in Perl's doc format: perldoc, POD.
The advantage of POD is the well formated output on various platforms, but
results in more difficult efforts for extracting information from there.
In particular following problems occoured with POD:
    - perldoc is not available on all platforms by default
    - POD is picky when text lines start with a whitespace
    - programatically extracting data requires additional substitutes
    - POD is slow

Changing POD to plain ASCII:
    equal source code: lines or kBytes in o-saft-usr.pm vs. o-saft-man.pm     

      Description              POD ASCII           %    File
    -------------------------+----+-------------+------+----------
    * reduced doc. text:      3110  2656 lines     85%  o-saft.pl
    * reduced doc. text:      86.9  85.5 kBytes    98%  o-saft.pl
    * reduced source code:     122    21 lines     17%  o-saft.pl
    * reduced source code:     4.4   1.0 kBytes    23%  o-saft.pl
    * improved performance:    2.7  0.02 seconds 0.75%  o-saft.pl
    -------------------------+----+-------------+------+----------


=head2 Note:SSL protocol versions

The phrases 'SSL protocol versions', 'SSL protocols' or simply 'protocols'
are used through out the comments in the sources equal for  SSLv2,  SSLv3,
TLSv1 etc..


=head2 Note:ALPN, NPN

Traditionally first known as NPN, the  "protocol negotiation",  is used in
in the two flaviours NPN and ALPN. The internal variable names are adapted
to these acronyms and use "alpn" and "npn" in their names.  For historical
reason, the list of the protocol names was stored in "cfg{'next_protos'}",
which reflects the openssl option (-nextprotoneg),  and the function names
used in some Perl modules.
As newer versions of openssl uses the option  -alpn,  and some other tools
also use  -alpn  and/or  -npn  as option, the internal variable names have
been adapted to this nameing scheme after version 17.04.17.
The primary variable names containing ALPN or NPN protocol names are now:

    protos_next     - internal list of all protocol names
    protos_alpn     - used with/for ALPN options
    protos_npn      - used with/for  NPN options
    cipher_alpns    - used with/for ALPN options for +cipher command only
    cipher_npns     - used with/for  NPN options for +cipher command only

I.g. these are arrays. But as the common syntax for most other tools is to
use a comma-separated list of names, the value in "cfg{'protos_next'}"  is
stored as a string. Using a string instead of an arrays also simplifies to
pass the value to functions.

Note: openssl uses a comma-separated list for ALPN and NPN,  but it uses a
colon-separated list for ecliptic curves (and also for ciphers).  Hence we
allow both separators for all lists on command line.

See also Note:OpenSSL Version


=head2 Note:alias

The code for parsing options and arguments uses some special syntax:

* following comment at end of the line:

    # alias: any other text

is used for aliases of commands or options. These lines are extracted by
   --help=alias


=head2 Note:ignore-out

The option  --no-cmd  uses the commands defined in "cfg{'ignore-out'}".
Results of these commands are not printed in output. # Purpose is to avoid
The purpose is to avoid  printing the results of these commands in output,
because the output is too noisy (like some +bsi* commands).
All data collections and checks are still done, just output of results are
omitted. Technically these commands are not removed from cfg{do}, but just
skipped in printdata() and printchecks(),  which makes implementation much
easier.


=head2 Note:OpenSSL Version

About OpenSSL's version numbers see openssl/opensslv.h . Examples:

  0x01000000 => openssl-0.9x.x
  0x1000000f => openssl-1.0.0
  0x10001000 => openssl-1.0.1
  0x10002000 => openssl-1.0.2
  0x102031af => 1.2.3z


=head2 Note:OpenSSL CApath

_init_openssldir() gets the configured directory for the certificate files
from the openssl executable. It is expected that openssl returns something
like:  OPENSSLDIR: "/usr/local/openssl"

Some versions of openssl on windows may return "/usr/local/ssl", or alike,
which is most likely wrong. As the existance of the returned directoy will
be checked, this produces an  **WARNING  and unsets the ca_path.  However,
the used Perl modules (i.e. Net::SSLeay)  may be compiled with a different
OPenSSL, and hence use their (compiled-in) private path to the certs.

Note that the returned OPENSSLDIR is a base-directory where the cert files
are found in the cert/ sub-directory. This cert/ is hardcoded herein.


=head2 Note:OpenSSL s_client

Example of% openssl s_client --help

 unknown option --help
 usage: s_client args

 -host host     - use -connect instead
 -port port     - use -connect instead
 -connect host:port - who to connect to (default is localhost:4433)
 -proxy host:port - use HTTP proxy to connect
 -verify_host host - check peer certificate matches "host"
 -verify_email email - check peer certificate matches "email"
 -verify_ip ipaddr - check peer certificate matches "ipaddr"
 -verify arg   - turn on peer certificate verification
 -verify_return_error - return verification errors
 -cert arg     - certificate file to use, PEM format assumed
 -certform arg - certificate format (PEM or DER) PEM default
 -key arg      - Private key file to use, in cert file if
                 not specified but cert file is.
 -keyform arg  - key format (PEM or DER) PEM default
 -pass arg     - private key file pass phrase source
 -CApath arg   - PEM format directory of CA's
 -CAfile arg   - PEM format file of CA's
 -no_alt_chains - only ever use the first certificate chain found
 -reconnect    - Drop and re-make the connection with the same Session-ID
 -pause        - sleep(1) after each read(2) and write(2) system call
 -prexit       - print session information even on connection failure
 -showcerts    - show all certificates in the chain
 -debug        - extra output
 -msg          - Show protocol messages
 -nbio_test    - more ssl protocol testing
 -state        - print the 'ssl' states
 -nbio         - Run with non-blocking IO
 -crlf         - convert LF from terminal into CRLF
 -quiet        - no s_client output
 -ign_eof      - ignore input eof (default when -quiet)
 -no_ign_eof   - don't ignore input eof
 -psk_identity arg - PSK identity
 -psk arg      - PSK in hex (without 0x)
 -srpuser user     - SRP authentification for 'user'
 -srppass arg      - password for 'user'
 -srp_lateuser     - SRP username into second ClientHello message
 -srp_moregroups   - Tolerate other than the known g N values.
 -srp_strength int - minimal length in bits for N (default 1024).
 -ssl2         - just use SSLv2
 -ssl3         - just use SSLv3
 -tls1_2       - just use TLSv1.2
 -tls1_1       - just use TLSv1.1
 -tls1         - just use TLSv1
 -dtls1        - just use DTLSv1
 -fallback_scsv - send TLS_FALLBACK_SCSV
 -mtu          - set the link layer MTU
 -no_tls1_2/-no_tls1_1/-no_tls1/-no_ssl3/-no_ssl2 - turn off that protocol
 -bugs         - Switch on all SSL implementation bug workarounds
 -serverpref   - Use server's cipher preferences (only SSLv2)
 -cipher       - preferred cipher to use, use the 'openssl ciphers'
                 command to see what is available
 -starttls prot - use the STARTTLS command before starting TLS
                 for those protocols that support it, where
                 'prot' defines which one to assume.  Currently,
                 only "smtp", "pop3", "imap", "ftp", "xmpp"
                 "telnet" and "ldap" are supported.
                 are supported.
 -xmpphost host - When used with "-starttls xmpp" specifies the virtual host.
 -engine id    - Initialise and use the specified engine
 -rand file:file:...
 -sess_out arg - file to write SSL session to
 -sess_in arg  - file to read SSL session from
 -servername host  - Set TLS extension servername in ClientHello
 -tlsextdebug      - hex dump of all TLS extensions received
 -status           - request certificate status from server
 -no_ticket        - disable use of RFC4507bis session tickets
 -serverinfo types - send empty ClientHello extensions (comma-separated numbers)
 -curves arg       - Elliptic curves to advertise (colon-separated list)
 -sigalgs arg      - Signature algorithms to support (colon-separated list)
 -client_sigalgs arg - Signature algorithms to support for client
                       certificate authentication (colon-separated list)
 -nextprotoneg arg - enable NPN extension, considering named protocols supported (comma-separated list)
 -alpn arg         - enable ALPN extension, considering named protocols supported (comma-separated list)
 -legacy_renegotiation - enable use of legacy renegotiation (dangerous)
 -use_srtp profiles - Offer SRTP key management with a colon-separated profile list
 -keymatexport label   - Export keying material using label
 -keymatexportlen len  - Export len bytes of keying material (default 20)
 -no_tlsext        - Don't send any TLS extensions (breaks servername, NPN and ALPN among others)

Some options are implemented for s_client, see Net::SSLinfo.pm , or use:
perl -MNet::SSLinfo -e 'print join("\n",Net::SSLinfo::s_client_get_optionlist());'


=head2 Note:Selected Protocol

'sslversion' returns protocol as used in our data structure (like TLSv12)

example (ouput from openssl):

    New, TLSv1/SSLv3, Cipher is ECDHE-RSA-AES128-GCM-SHA256

example Net::SSLeay:

    Net::SSLeay::version(..)

example (ouput from openssl):
'session_protocol' retruns string used by openssl (like TLSv1.2)

    Protocol  : TLSv1.2

'fallback_protocol'

    Note: ouput from openssl:       TLSv1.2
    Note: output from Net::SSLeay:  TLSv1_2


=head2 Note:Selected Cipher

SEE Note:term default cipher.

'cipher_selected' returns the cipher as used in our data structure (like
 DHE-DES-CBC), this is the one selected if the client provided a list
example (ouput from openssl):

example Net::SSLeay:
        Net::SSLeay::get_cipher(..)


=head2 Note:Connection test

To avoid long timouts, a quick connection check to the target is done.  At
least the connection to the SSL port must succeed.  If not, all checks are
skipped. If just the connection to port 80 fails, just the HTTP checks are
disabled. Also SEE Note:--ssl-error .

The initial connection check just opens the port and does nothing. This is
done because  some methods, i.e.  Net::SSLeay::get_http(),  do not support
timeout settings, which then results in "hanging" connections.


=head2 Note:--ssl-error

The option  --ssl-error  in conjunction with error counts  --ssl-error-max
and --ssl-error-total controls wether to try to connect to the target even
if there are errors or timeouts. I.g. the used API IO::Socket:SSL, openssl
returns an error in $!. Unfortunately the error may be different according
the used version.  Hence the check herein  does not use the returned error
but relies on the time passed during the connection.  The assumtion (based
on experiance) is, that successful or rejected connection take less than a
second, even on slow connections.  If the connection cannot be established
(because not supported or blocked), we run into a timeout, which is always
more than 0, at least 1 second (see --timeout=SEC option).

Timeout cannot be set less than  one second.  Also measuring the times and
their difference is in seconds.  A more accurate time measurement requires
the Time::Local module, which we try to avoid.  Measureing within a second
is sufficent for these checks.

More descriptions are in the section  LIMITATIONS  of the man page, see

   "Connection Problems"  there.


=head2 Note:%prot

Using SSL/TLS protocols can either be done using %prot or $cfg{'versions'}
in contrast to "keys %prot"  $cfg{'versions'} is sorted according protocol
like: SSLv2 SSLv3 TLSv1 ...


=head2 Note:--exitcode

Ideas and discussions see also: https://github.com/OWASP/O-Saft/issues/52
By default  --exitcode  counts all settings considered weak or insecure.
This behaviour can be controlled with the  --exitcode-no-*  options.


=head2 Note:heartbleed

http://heartbleed.com/
http://possible.lv/tools/hb/
http://filippo.io/Heartbleed/
https://github.com/proactiveRISK/Heartbleed
https://www.cloudflarechallenge.com/heartbleed
See also "--ignore-no-reply" description in o-saft-man.pm.

Apache cannot disable heartbeat, see:
??

nginx cannot disable heartbeat, see:
https://www.nginx.com/blog/nginx-and-the-heartbleed-vulnerability/


=head2 Note:ticketbleed


=head2 Note:CGI mode

In CGI mode all options are passed with a trailing  =  even those which do
not have an argument (value). This means that options cannot be ignored in
general, because they may occour at least in CGI mode, i.e.  --cmd=  .
The trailing  =  can always be removed, empty values are not possible.


=head2 Note:Stand-alone

A stand-alone script is a single script,  which executes without any other
module to be included (read) at run-time.
Most modules --means modules in Perl context and syntax-- are already read
using a private function  _load_file(),  which uses Perl's require instead
of use. This way the modules are loaded at  run-time (require)  and not at
compile-time (use).
Unfortunately there exist modules, which must be loaded with Perl's use.
When generating a stand-alone executable script, the complete file of each
module is simply copied into the main script file (o-saft.pl usually).  In
that case, the corresponding use statement must be removed. Modules loaded
with  _load_file()  read the files only if the variable  $osaft_standalone
does not exist.
Please refer to the  INSTALLATION  section,  in particular the sub-section
Stand-alone Executable  there, for more details on generating  stand-alone
scripts.
Generating a stand-alone script is done by contrib/gen_standalone.sh .


=head2 Note:root-CA

Some texts from: http://www.zytrax.com/tech/survival/ssl.html
The term Certificate Authority is defined as being an entity which signs
certificates in which the following are true:

 * the issuer and subject fields are the same,
 * the KeyUsage field has keyCertSign set
 * and/or the basicConstraints field has the cA attribute set TRUE.

Typically, in chained certificates the root CA certificate is the topmost
in the chain but RFC 4210 defines a 'root CA' to be any issuer for which
the end-entity, for example, the browser has a certificate which was obtained
by a trusted out-of-band process. Since final authority for issuing any
certificate rest with this CA the terms and conditions of any intermediate
certificate may be modified by this entity.


Subordinate Authority:
may be marked as CAs (the extension BasicContraints will be present and cA will be set True)


Intermediate Authority (a.k.a. Intermediate CA):
Imprecise term occasionally used to define an entity which creates an
intermediate certificate and could thus encompass an RA or a subordinate CA.


Cross certificates (a.k.a. Chain or Bridge certificate):
A cross-certificate is one in which the subject and the issuer are not the
same but in both cases they are CAs (BasicConstraints extension is present and has cA set True).


Intermediate certificates (a.k.a. Chain certificates):
Imprecise term applied to any certificate which is not signed by a root CA.
The term chain in this context is meaningless (but sounds complicated and
expensive) and simply indicates that the certificate forms part of a chain.


Qualified certificates: Defined in RFC 3739
the term Qualified certificates relates to personal certificates (rather than
server certificates) and references the European Directive on Electronic Signature (1999/93/EC)
see check02102() above


Multi-host certificates (a.k.a wildcard certificates)

EV Certificates (a.k.a. Extended Certificates): Extended Validation (EV)
certificates are distinguished by the presence of the CertificatePolicies
extension containg a registered OID in the policyIdentifier field.
see checkev() above

  RFC 3280
   4.2.1.10  Basic Constraints
     X509v3 Basic Constraints:
         cA:FALSE
         pathLenConstraint  INTEGER (0..MAX) OPTIONAL )
  RFC 4158


=head2 Note:term default cipher

Technically SSL/TLS does not know about a "default cipher".  Starting with
TLSv1 it can provide a "prefered selected cipher". The server then selects
a cipher which is common between its own list of ciphers and the list send
by the client. The more correct term therfore is  "prefered" or "selected"
cipher.
Many documents still use the term "default".  Some code exists, which also
uses "default" as part of variable or function names.


=head2 Note:+cipherall

SEE Note:term default cipher.

In October 2017 (VERSION 17.09.17), the +cipherall command is no longer an
alias for +cipherraw. It is now using the the same technique as +cipherraw
to detect the targets ciphers, but prints the results like the traditional
+cipher command.
This has some impacts on computing other checks, like the default selected
cipher, the strongest and weakest selected cipher.

One problem is, that  +cipher  itself cannot detect the default cipher, so
it uses the underlaying SSL library's methods to do it, see _get_default()
which also computes the strongest and weakest selected cipher.
When using +cipherraw another method to detect these ciphers must be used;
this is not yet implemented completely.
The problem should finally be solved when  +cipher and +cipherraw  use the
same data structre for the results. Then the program flow should be like:

   ciphers_scan()
   checkciphers()
   printciphers()
   printciphersummary()


=cut
