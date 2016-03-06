#!/usr/bin/perl -w

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
#!# "Program Code" in  o-saft-man.pm  if you want to improve the program.

# NOTE
#       Perl's  `use' and `require' will be used for common and well known perl
#       modules only. All other modules, in particular our own ones, are loaded
#       using an internal function, see _load_file().  All required modules are
#       included as needed. This keeps away noisy messages and allows to be run
#       and print some information even if installed incompletely.

use strict;

use constant {
    SID         => "@(#) yeast.pl 1.434b 16/03/04 23:59:59",
    STR_VERSION => "07.01.16",          # <== our official version number
    STR_ERROR   => "**ERROR: ",
    STR_WARN    => "**WARNING: ",
    STR_HINT    => "**Hint: ",
    STR_USAGE   => "**USAGE: ",
    STR_DBX     => "#dbx# ", 
    STR_UNDEF   => "<<undef>>",
    STR_NOTXT   => "<<>>",
};
sub _y_TIME($) { # print timestamp if --trace-time was given; similar to _y_CMD
    # need to check @ARGV directly as this is called before any options are parsed
    if (grep(/(:?--trace.*time)/i, @ARGV) > 0) {
        printf("#o-saft.pl  %02s:%02s:%02s CMD: %s\n", (localtime)[2,1,0], @_);
    }
}
sub _y_EXIT($) { # exit if parameter matches given argument in @ARGV
    my $txt =  shift;
    my $arg =  $txt;
       $arg =~ s# .*##; # strip off anything right of a space
    if (grep(/(:?([+]|--)$arg).*/i, @ARGV) > 0) {
        printf STDERR ("#o-saft.pl  _y_EXIT $txt\n");
        exit 0;
    }
}

BEGIN {
    _y_TIME("BEGIN{");
    _y_EXIT("exit=BEGIN0 - BEGIN start");
    sub _VERSION() { return STR_VERSION; }  # required in o-saft-man.pm
    # Loading `require'd  files and modules as well as parsing the command line
    # in this scope  would increase performance and lower the memory foot print
    # for some commands (see o-saft-man.pm also).
    # Unfortunately perl's BEGIN has following limits and restrictions:
    #   - constants can be defined before and used herein 
    #   - sub can be defined herein and used later
    #   - variables can not be defined herein and used later
    #   - some file handles (like <DATA>) are not yet available
    #   - strict sequence of definitions and usage (even for variables in subs)
    # subs used in the BEGIN block must be defined in the BEGIN block or before
    # the BEGIN block (which is a crazy behaviour of perl).
    # To make the program work as needed,  these limitations would force to use
    # some dirty code hacks and split the flow of processing in different parts
    # of the source. Therefore this scope is used for --help=* options only.

    my $_me   = $0; $_me   =~ s#.*[/\\]##;
    my $_path = $0; $_path =~ s#[/\\][^/\\]*$##;
    unshift(@INC,                   # NOTE that / works here even for Windoze
            "./", "./lib",          # we support some local lib directories
            $_path,                 # user-friendly: add path of myself also
            "/bin",                 # special installation on portable media
    );

    # handle simple help very quickly
    if (grep(/^(?:--|\+)VERSION/, @ARGV) > 0) { print STR_VERSION . "\n"; exit 0; }
    print STDERR STR_WARN, "on $^O additional option  --v  required, sometimes ...\n" if ($^O =~ m/MSWin32/);
        # be smart to users if systems behave strange :-/
    # get first matching argument
    my ($arg) = grep(/^(?:--h(?:elp)?|\+help|(?:--|\+)help=?(?:gen-)?(?:opts?|commands?|cgi|html|wiki|abbr|abk|glossar|[A-Z]+))$/, @ARGV);
        # we allow:  --h  or  --help  or  +help  or  +help=SOMETHING
        # for historic reason this allows: +abbr +abk +glossar +todo
    if (defined $arg) {
        $arg =~ s/^(?:--|\+)//;     # remove option prefix
        $arg =~ s/^help=?//;        # remove option but keep its argument
        $arg =~ s/^h$//;            # --h is same as --help
        require "o-saft-man.pm";    # must be found with @INC; dies if missing
        printhelp($arg);            # empty $arg for full help text
        exit 0;
    }
    _y_EXIT("exit=BEGIN1 - BEGIN end");
} # BEGIN
_y_TIME("BEGIN}");                  # missing for +VERSION, however, +VERSION --trace-TIME makes no sense
_y_EXIT("exit=INIT0 - initialization start");

our $VERSION= STR_VERSION;
our $me     = $0; $me     =~ s#.*[/\\]##;
our $mepath = $0; $mepath =~ s#/[^/\\]*$##;
    $mepath = "./" if ($mepath eq $me);
our $mename = "yeast  ";
    $mename = "O-Saft " if ($me !~ /yeast/);

# now set @INC
# NOTE: do not use "-I . lib/" in hashbang line as it will be pre- and appended
unshift(@INC, "$mepath", "$mepath/lib");
#_dbx "INC: ".join(" ",@INC) . "\n";

my  $arg    = "";
my  @argv   = ();   # all options, including those from RC-FILE
                    # will be used when ever possible instead of @ARGV
# arrays to collect data for debugging, they are global!
our @dbxarg;        # normal options and arguments
our @dbxcfg;        # config options and arguments
our @dbxexe;        # executable, library, environment
our @dbxfile;       # read files
our $warning= 1;    # print warnings; need this variable very early

binmode(STDOUT, ":unix");
binmode(STDERR, ":unix");

## definitions: forward declarations
## -------------------------------------
sub __SSLinfo($$$);
sub _is_intern($);  # perl avoid: main::_is_member() called too early to check prototype
sub _is_member($$); #   "
sub _initchecks_prot();

## README if any
## -------------------------------------
open(RC, '<', "o-saft-README") && do { print <RC>; close(RC); exit 0; };

## CGI
## -------------------------------------
our $cgi  = 0;
if ($me =~/\.cgi$/) {
    # CGI mode is pretty simple: see {yeast,o-saft}.cgi
    #   code removed here! hence it always fails
    die STR_ERROR, "CGI mode requires strict settings" if (grep(/--cgi=?/, @ARGV) <= 0);
    $cgi = 1;
} # CGI

## definitions: debug and tracing
## -------------------------------------
# functions and variables used very early in main
our %cfg =  ('trace' => 0 ); # used in usr_pre_init(); avoid: Use of uninitialized value ...
sub _dprint { local $\ = "\n"; print STDERR STR_DBX, join(" ", @_); }
sub _dbx    { _dprint(@_); } # alias for _dprint
sub _warn   {
    #? print warning if wanted
    # don't print if ($warning <= 0);
    return if (grep(/(:?--no.?warn)/i, @ARGV) > 0);     # ugly hack 'cause we won't pass $warning
    local $\ = "\n"; print(STR_WARN, join(" ", @_));
    # TODO: in CGI mode warning must be avoided until HTTP header written
}
sub _warn_and_exit {
    #? print warning that --experimental option is required
    #-method:  name of function where this message is called
    #-command: name of command subject to this message
    local $\ = "\n";
    if (grep(/(:?--experimental)/i, @ARGV) > 0) {
        my $method = shift;
        _trace("_warn_and_exit $method: " . join(" ", @_));
    } else {
        printf(STR_WARN, "(%s) --experimental option required to use '%s' functionality. Please send us your feedback about this functionality to o-saft(at)lists.owasp.org\n", @_);
        exit(1);
    }
}
sub _print_read($$) { printf("=== reading: %s (%s) ===\n", @_) if (grep(/(:?--no.?header|--cgi)/i, @ARGV) <= 0); }
    # print information what will be read
        # $cgi not available, hence we use @ARGV (may contain --cgi or --cgi-exec)
        # $cfg{'out_header'} not yet available, see LIMITATIONS also

sub _load_file($$) {
    # load file with perl's require using the paths in @INC
    # use `$0 +version --v'  to see which files are loaded
    my $fil = shift;
    my $txt = shift;
    my $err = "";
    eval("require '$fil';"); # need eval to catch "Can't locate ... in @INC ..."
    $err = $@;
    chomp $err;
    if ($err eq "") {
        $txt = "$txt done";
        $INC{$fil} = "." . $INC{$fil} if ("/$fil" eq $INC{$fil}); # fix ugly %INC
        # FIXME: above fix fails for NET::SSL* and absolute path like --trace=/file
        $fil = $INC{$fil};
    } else {
        $txt = "$txt failed";
        $fil = "<<no $fil>>";
    }
    push(@dbxfile, $fil);
    _print_read($fil, $txt);
    return $err;
} # _load_file

## read RC-FILE if any
## -------------------------------------
_y_TIME("cfg{");
_y_EXIT("exit=CONF0 - RC-FILE start");
my @rc_argv = "";
$arg = "./.$me";    # check in pwd only
if (grep(/(:?--no.?rc)$/i, @ARGV) <= 0) {   # only if not inhibited
    if (open(RC, '<', "$arg")) {
        push(@dbxfile, $arg);
        _print_read("$arg", "RC-FILE done");
        @rc_argv = grep(!/\s*#[^\r\n]*/, <RC>); # remove comment lines
        @rc_argv = grep(s/[\r\n]//, @rc_argv);  # remove newlines
        close(RC);
        push(@argv, @rc_argv);
        #dbx# _dbx ".RC: " . join(" ", @rc_argv) . "\n";
    } else {
        _print_read("$arg", "RC-FILE: $!") if (grep(/--v/i, @ARGV) > 0);;
    }
}
_y_EXIT("exit=CONF0 - RC-FILE start");

push(@argv, @ARGV); # got all now
push(@ARGV, "--no-header") if grep(/--no-?header/, @argv); # if defined in RC-FILE, needed in _warn()
# FIXME: (10) { following will be added when %cfg is defined in o-saft-cfg.pm
# $cfg{'ARG0'}    = $0;
# $cfg{'ARGV'}    = [@ARGV];
# $cfg{'RC-ARGV'} = [@rc_argv];
# $cfg{'RC-FILE'} = "./.$me";
# FIXME: (10) } # see other FIXME 10 too

## read DEBUG-FILE, if any (source for trace and verbose)
## -------------------------------------
my $err = "";
my @dbx = grep(/--(?:trace|v$|yeast)/, @argv);  # may have --trace=./file
if (($#dbx >= 0) and (grep(/--cgi=?/,@argv) <= 0)) {
    $arg =  "o-saft-dbx.pm";
    $arg =  $dbx[0] if ($dbx[0] =~ m#/#);
    $arg =~ s#[^=]+=##; # --trace=./myfile.pl
    $err = _load_file($arg, "trace file");
    if ($err ne "") {
        die STR_ERROR, "$err" unless (-e $arg);
        # no need to continue if file with debug functions does not exist
        # NOTE: if $mepath or $0 is a symbolic link, above checks fail
        #       we don't fix that! Workaround: install file in ./
    }
} else {
    # debug functions are defined in o-saft-dbx.pm and loaded on demand
    # they must be defined always as they are used wheter requested or not
    sub _yeast_init() {}
    sub _yeast_exit() {}
    sub _yeast_args() {}
    sub _yeast_data() {}
    sub _yeast($)     {}
    sub _y_ARG        {}
    sub _y_CMD        {}
    sub _v_print      {}
    sub _v2print      {}
    sub _v3print      {}
    sub _v4print      {}
    sub _vprintme     {}
    sub _trace($)     {}
    sub _trace1($)    {}
    sub _trace2($)    {}
    sub _trace3($)    {}
    sub _trace_cmd($) {}
}

## read USER-FILE, if any (source with user-specified code)
## -------------------------------------
if (grep(/--(?:use?r)/, @argv) > 0) { # must have any --usr option
    $err = _load_file("o-saft-usr.pm", "user file");
    if ($err ne "") {
        # continue without warning, it's already printed in "=== reading: " line
        sub usr_version()   { return ""; }; # dummy stub, see o-saft-usr.pm
        sub usr_pre_init()  {}; #  "
        sub usr_pre_file()  {}; #  "
        sub usr_pre_args()  {}; #  "
        sub usr_pre_exec()  {}; #  "
        sub usr_pre_cipher(){}; #  "
        sub usr_pre_main()  {}; #  "
        sub usr_pre_host()  {}; #  "
        sub usr_pre_info()  {}; #  "
        sub usr_pre_open()  {}; #  "
        sub usr_pre_cmds()  {}; #  "
        sub usr_pre_data()  {}; #  "
        sub usr_pre_print() {}; #  "
        sub usr_pre_next()  {}; #  "
        sub usr_pre_exit()  {}; #  "
    }
}

usr_pre_init();

## initialize defaults
## -------------------------------------
#!# set defaults
#!# -------------------------------------
#!# To make (programmer's) life simple, we try to avoid complex data structure,
#!# which are error-prone, by using a couple of global variables.
#!# As there are no plans to run this tool in threaded mode, this should be ok.
#!# Please see "Program Code" in o-saft-man.pm too.
#!#
#!# Here's an overview of the used global variables:
#!#   $me             - the program name or script name with path stripped off
#!#   $mepath         - the path where program or script ($me) is located
#!#   $mename         - my name pretty printed
#!#   %prot           - collected data per protocol (from Net::SSLinfo)
#!#   %prot_txt       - labes for %prot
#!#   @results        - where we store the results as:  [SSL, cipher, "yes|no"]
#!#   %data           - labels and correspondig value (from Net::SSLinfo)
#!#   %checks         - collected and checked certificate data
#!#                     collected and checked target (connection) data
#!#                     collected and checked connection data
#!#                     collected and checked length and count data
#!#                     HTTP vs. HTTPS checks
#!#   %shorttexts     - same as %checks, but short texts
#!#   %cmd            - configuration for external commands
#!#   %cfg            - configuration for commands and options herein
#!#   %text           - configuration for message texts
#!#   %scores         - scoring values
#!#   %ciphers_desc   - description of %ciphers data structure
#!#   %ciphers        - our ciphers
#!#   %cipher_names   - (hash)map of cipher constant-names to names
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

my ($key,$sec,$ssl);# some temporary variables used in main
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

our @results= ();   # list of checked ciphers: [PROT, ciper suite name, yes|no]
our %prot   = (     # collected data for protocols and ciphers
    # NOTE: ssl must be same string as in %cfg, %ciphers[ssl] and Net::SSLinfo %_SSLmap
    # ssl           protocol  name        hex version value openssl  option     val LOW ...
    #--------------+---------------------+-----------------+-------------------+---+---+---+---
    'SSLv2'     => {'txt' => "SSL 2.0 ",  'hex' => 0x0002,  'opt' => "-ssl2"    },
    'SSLv3'     => {'txt' => "SSL 3.0 ",  'hex' => 0x0300,  'opt' => "-ssl3"    },
    'TLSv1'     => {'txt' => "TLS 1.0 ",  'hex' => 0x0301,  'opt' => "-tls1"    },
    'TLSv11'    => {'txt' => "TLS 1.1 ",  'hex' => 0x0302,  'opt' => "-tls1_1"  },
    'TLSv12'    => {'txt' => "TLS 1.2 ",  'hex' => 0x0303,  'opt' => "-tls1_2"  },
    'TLSv13'    => {'txt' => "TLS 1.3 ",  'hex' => 0x0304,  'opt' => "-tls1_3"  },
    'DTLSv09'   => {'txt' => "DTLS 0.9",  'hex' => 0x0100,  'opt' => "-dtls"    },  # see Notes
    'DTLSv1'    => {'txt' => "DTLS 1.0",  'hex' => 0xFEFF,  'opt' => "-dtls1"   },  #  "
    'DTLSv11'   => {'txt' => "DTLS 1.1",  'hex' => 0xFEFE,  'opt' => "-dtls1_1" },  #  "
    'DTLSv12'   => {'txt' => "DTLS 1.2",  'hex' => 0xFEFD,  'opt' => "-dtls1_2" },  #  "
    'DTLSv13'   => {'txt' => "DTLS 1.3",  'hex' => 0xFEFC,  'opt' => "-dtls1_3" },  #  "
    'TLS1FF'    => {'txt' => "--dummy--", 'hex' => 0x03FF,  'opt' => undef      },  #  "
    'DTLSfamily'=> {'txt' => "--dummy--", 'hex' => 0xFE00,  'opt' => undef      },  #  "
   #'TLS_FALLBACK_SCSV'=>{'txt'=> "SCSV", 'hex' => 0x5600,  'opt' => undef      },
    #-----------------------+--------------+----------------+------------------+---+---+---+---
    # "protocol"=> {cnt, WEAK, LOW, MEDIUM, HIGH, pfs, default, protocol} see _initchecks_prot()
    # Notes:
    #  TLS1FF   0x03FF  # last possible version of TLS1.x (not specified, used internal)
    #  DTLSv09: 0x0100  # DTLS, OpenSSL pre 0.9.8f, not finally standardized; some versions use 0xFEFF
    #  DTLSv09: -dtls   # never defined and used in openssl
    #  DTLSv1   0xFEFF  # DTLS1.0 (udp)
    #  DTLSv11  0xFEFE  # DTLS1.1: has never been used (udp)
    #  DTLSv12  0xFEFD  # DTLS1.2 (udp)
    #  DTLSv13  0xFEFC  # DTLS1.3, NOT YET specified (udp)
    #  DTLSfamily       # DTLS1.FF, no defined PROTOCOL, for internal use only
    # 'hex' value will be copied to $cfg{'openssl_version_map'} below
    # 'opt' value will be copied to $cfg{'openssl_option_map'}  below
    # TODO: hex value should be same as %_SSLmap in Net::SSLinfo
); # %prot
_initchecks_prot(); # initallize WEAK, LOW, MEDIUM, HIGH, default, pfs, protocol
our %prot_txt = (
    'cnt'           => "Supported total ciphers for ",           # counter; $ssl added in print*()
    '-?-'           => "Supported ciphers with security unknown",#  "
    'WEAK'          => "Supported ciphers with security WEAK",   #  "
    'LOW'           => "Supported ciphers with security LOW",    #  "
    'MEDIUM'        => "Supported ciphers with security MEDIUM", #  "
    'HIGH'          => "Supported ciphers with security HIGH",   #  "
    'pfs_ciphers'   => "PFS (all  ciphers)",            # list with PFS ciphers
    'pfs_cipher'    => "PFS (selected cipher)",         # cipher if offered as default
    'default'       => "Selected  cipher  by server",   # cipher offered as default
    'protocol'      => "Selected protocol by server",   # 1 if selected as default protocol
); # %prot_txt

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
    'selected'      => {'val' => sub { Net::SSLinfo::selected(      $_[0], $_[1])}, 'txt' => "Selected Cipher"},
    'ciphers_openssl'=>{'val' => sub { $_[0] },                                     'txt' => "OpenSSL Ciphers"},
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
    'tlsextdebug'   => {'val' => sub { __SSLinfo('tlsextdebug',     $_[0], $_[1])}, 'txt' => "SSL extensions (debug)"},
    'tlsextensions' => {'val' => sub { __SSLinfo('tlsextensions',   $_[0], $_[1])}, 'txt' => "SSL extensions"},
    'ext_authority' => {'val' => sub { __SSLinfo('ext_authority',   $_[0], $_[1])}, 'txt' => "Certificate extensions Authority Information Access"},
    'ext_authorityid'=>{'val' => sub { __SSLinfo('ext_authorityid', $_[0], $_[1])}, 'txt' => "Certificate extensions Authority key Identifier"},
    'ext_constraints'=>{'val' => sub { __SSLinfo('ext_constraints', $_[0], $_[1])}, 'txt' => "Certificate extensions Basic Constraints"},
    'ext_cps'       => {'val' => sub { __SSLinfo('ext_cps',         $_[0], $_[1])}, 'txt' => "Certificate extensions Certificate Policies"},
    'ext_cps_policy'=> {'val' => sub { __SSLinfo('ext_cps_policy',  $_[0], $_[1])}, 'txt' => "Certificate extensions Certificate Policies: Policy"},
    'ext_subjectkeyid'=>{'val'=> sub { __SSLinfo('ext_subjectkeyid',$_[0], $_[1])}, 'txt' => "Certificate extensions Subject Key Identifier"},
    'ext_cps_cps'   => {'val' => sub { __SSLinfo('ext_cps_cps',     $_[0], $_[1])}, 'txt' => "Certificate extensions Certificate Policies: CPS"},
    'ext_crl'       => {'val' => sub { __SSLinfo('ext_crl',         $_[0], $_[1])}, 'txt' => "Certificate extensions CRL Distribution Points"},
    'ext_crl_crl'   => {'val' => sub { __SSLinfo('ext_crl_crL',     $_[0], $_[1])}, 'txt' => "Certificate extensions CRL Distribution Points: Full Name"},
    'ext_keyusage'  => {'val' => sub { __SSLinfo('ext_keyusage',    $_[0], $_[1])}, 'txt' => "Certificate extensions Key Usage"},
    'ext_extkeyusage'=>{'val' => sub { __SSLinfo('ext_extkeyusage', $_[0], $_[1])}, 'txt' => "Certificate extensions Extended Key Usage"},
    'ext_certtype'  => {'val' => sub { __SSLinfo('ext_certtype',    $_[0], $_[1])}, 'txt' => "Certificate extensions Netscape Cert Type"},
    'ext_issuer'    => {'val' => sub { __SSLinfo('ext_issuer',      $_[0], $_[1])}, 'txt' => "Certificate extensions Issuer Alternative Name"},
    'ocsp_uri'      => {'val' => sub { Net::SSLinfo::ocsp_uri(      $_[0], $_[1])}, 'txt' => "Certificate OCSP Responder URL"},
    'ocspid'        => {'val' => sub { Net::SSLinfo::ocspid(        $_[0], $_[1])}, 'txt' => "Certificate OCSP Subject, Public Key Hash"},
    'subject_hash'  => {'val' => sub { Net::SSLinfo::subject_hash(  $_[0], $_[1])}, 'txt' => "Certificate Subject Name Hash"},
    'issuer_hash'   => {'val' => sub { Net::SSLinfo::issuer_hash(   $_[0], $_[1])}, 'txt' => "Certificate Issuer Name Hash"},
    'selfsigned'    => {'val' => sub { Net::SSLinfo::selfsigned(    $_[0], $_[1])}, 'txt' => "Certificate Validity (signature)"},
    'fingerprint_type'=>{'val'=> sub { Net::SSLinfo::fingerprint_type($_[0],$_[1])},'txt' => "Certificate Fingerprint Algorithm"},
    'fingerprint_hash'=>{'val'=> sub { __SSLinfo('fingerprint_hash',$_[0], $_[1])}, 'txt' => "Certificate Fingerprint Hash Value"},
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
    'protocols'     => {'val' => sub { Net::SSLinfo::protocols(     $_[0], $_[1])}, 'txt' => "Target advertised protocols"},
    'alpn'          => {'val' => sub { Net::SSLinfo::alpn(          $_[0], $_[1])}, 'txt' => "Target's selected protocol (ALPN)"},
    'no_alpn'       => {'val' => sub { Net::SSLinfo::no_alpn(       $_[0], $_[1])}, 'txt' => "Target's not ngotiated message (ALPN)"},
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
    'https_sts'     => {'val' => sub { Net::SSLinfo::https_sts(     $_[0], $_[1])}, 'txt' => "HTTPS STS header"},
    'hsts_maxage'   => {'val' => sub { Net::SSLinfo::hsts_maxage(   $_[0], $_[1])}, 'txt' => "HTTPS STS MaxAge"},
    'hsts_subdom'   => {'val' => sub { Net::SSLinfo::hsts_subdom(   $_[0], $_[1])}, 'txt' => "HTTPS STS include sub-domains"},
    'http_protocols'=> {'val' => sub { Net::SSLinfo::http_protocols($_[0], $_[1])}, 'txt' => "HTTP Alternate-Protocol"},
    'http_svc'      => {'val' => sub { Net::SSLinfo::http_svc(      $_[0], $_[1])}, 'txt' => "HTTP Alt-Svc header"},
    'http_status'   => {'val' => sub { Net::SSLinfo::http_status(   $_[0], $_[1])}, 'txt' => "HTTP Status line"},
    'http_location' => {'val' => sub { Net::SSLinfo::http_location( $_[0], $_[1])}, 'txt' => "HTTP Location header"},
    'http_refresh'  => {'val' => sub { Net::SSLinfo::http_refresh(  $_[0], $_[1])}, 'txt' => "HTTP Refresh header"},
    'http_sts'      => {'val' => sub { Net::SSLinfo::http_sts(      $_[0], $_[1])}, 'txt' => "HTTP STS header"},
    #------------------+---------------------------------------+-------------------------------------------------------
    'options'       => {'val' => sub { Net::SSLinfo::options(       $_[0], $_[1])}, 'txt' => "<<internal>> used SSL options bitmask"},
    #------------------+---------------------------------------+-------------------------------------------------------
    # following not printed by default, but can be used as command
#   'PROT'          => {'val' => sub { return $prot{'PROT'}->{'default'}         }, 'txt' => "Target default PROT     cipher"}, #####
    # all others will be added below
    #------------------+---------------------------------------+-------------------------------------------------------
    # following are used for checkdates() only, they must not be a command!
    # they are not printed with +info or +check; values are integer
    'valid-years'   => {'val' =>  0, 'txt' => "certificate validity in years"},
    'valid-months'  => {'val' =>  0, 'txt' => "certificate validity in months"},
    'valid-days'    => {'val' =>  0, 'txt' => "certificate validity in days"},  # approx. value, accurate if < 30
); # %data
# need s_client for: compression|expansion|selfsigned|chain|verify|resumption|renegotiation|protocols|
# need s_client for: krb5|psk_hint|psk_identity|srp|master_key|session_id|session_protocol|session_ticket|session_lifetime|session_timeout

# add keys from %prot to %data,
foreach $ssl (keys %prot) {
    $key = lc($ssl); # keys in data are all lowercase (see: convert all +CMD)
    $data{$key}->{val} = sub {    return $prot{$ssl}->{'default'}; };
    $data{$key}->{txt} = "Target default $prot{$ssl}->{txt} cipher";
}

our %checks = (
    # key           =>  {val => "", txt => "label to be printed", score => 0, typ => "connection"},
    #
    # default for 'val' is "" (empty string), default for 'score' is 0
    # 'typ' is any of certificate, connection, destination, https, sizes
    # both will be set in sub _init_all(), please see below

    # the default value means "check = ok/yes", otherwise: "check =failed/no"

); # %checks

my %check_cert = (  # certificate data
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
    'ocsp'          => {'txt' => "Certificate has OCSP Responder URL"},
    'cps'           => {'txt' => "Certificate has Certification Practice Statement"},
    'crl'           => {'txt' => "Certificate has CRL Distribution Points"},
    'zlib'          => {'txt' => "Certificate has (TLS extension) compression"},
    'lzo'           => {'txt' => "Certificate has (GnuTLS extension) compression"},
    'open_pgp'      => {'txt' => "Certificate has (TLS extension) authentication"},
    'sernumber'     => {'txt' => "Certificate Serial Number size RFC5280"},
    'constraints'   => {'txt' => "Certificate Basic Constraints is false"},
    'sha2signature' => {'txt' => "Certificate Private Key Signature SHA2"},
    'modulus_size'  => {'txt' => "Certificate Public Key Modulus <16385 bits"},
    'modulus_exp_size'=>{'txt'=> "Certificate Public Key Modulus Exponent <65537"},
    'pub_encryption'=> {'txt' => "Certificate Public Key with Encryption"},
    'pub_enc_known' => {'txt' => "Certificate Public Key Encryption known"},
    'sig_encryption'=> {'txt' => "Certificate Private Key with Encryption"},
    'sig_enc_known' => {'txt' => "Certificate Private Key Encryption known"},
    'rfc6125_names' => {'txt' => "Certificate Names compliant to RFC6125"},
    # following checks in subjectAltName, CRL, OCSP, CN, O, U
    'nonprint'      => {'txt' => "Certificate does not contain non-printable characters"},
    'crnlnull'      => {'txt' => "Certificate does not contain CR, NL, NULL characters"},
    'ev-chars'      => {'txt' => "Certificate has no invalid characters in extensions"},
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

my %check_conn = (  # connection data
    # collected and checked connection data
    #------------------+-----------------------------------------------------
    'ip'            => {'txt' => "IP for given hostname "},
    'reversehost'   => {'txt' => "Given hostname is same as reverse resolved hostname"},
    'hostname'      => {'txt' => "Connected hostname matches certificate's subject"},
    'beast'         => {'txt' => "Connection is safe against BEAST attack (any cipher)"},
    'breach'        => {'txt' => "Connection is safe against BREACH attack"},
    'crime'         => {'txt' => "Connection is safe against CRIME attack"},
    'time'          => {'txt' => "Connection is safe against TIME attack"},
    'freak'         => {'txt' => "Connection is safe against FREAK attack"},
    'heartbleed'    => {'txt' => "Connection is safe against Heartbleed attack"},
    'logjam'        => {'txt' => "Connection is safe against Logjam attack"},
    'lucky13'       => {'txt' => "Connection is safe against Lucky 13 attack"},
    'poodle'        => {'txt' => "Connection is safe against POODLE attack"},
    'rc4'           => {'txt' => "Connection is safe against RC4 attack"},
    'sloth'         => {'txt' => "Connection is safe against SLOTH attack"},
    'sni'           => {'txt' => "Connection is not based on SNI"},
    'selected'      => {'txt' => "Selected cipher by server"},
     # NOTE: following keys use mixed case letters, that's ok 'cause these
     #       checks are not called by their own commands; ugly hack ...
    #------------------+-----------------------------------------------------
); # %check_conn

my %check_dest = (  # target (connection) data
    # collected and checked target (connection) data
    #------------------+-----------------------------------------------------
    'sgc'           => {'txt' => "Target supports Server Gated Cryptography (SGC)"},
    'edh'           => {'txt' => "Target supports EDH ciphers"},
    'hassslv2'      => {'txt' => "Target does not support SSLv2"},
    'hassslv3'      => {'txt' => "Target does not support SSLv3"},      # POODLE
    'hastls10'      => {'txt' => "Target supports TLSv1"},
    'hastls11'      => {'txt' => "Target supports TLSv1.1"},
    'hastls12'      => {'txt' => "Target supports TLSv1.2"},
    'hastls13'      => {'txt' => "Target supports TLSv1.3"},
    'hasalpn'       => {'txt' => "Target supports Application Layer Protocol Negotiation (ALPN)"},
    'npn'           => {'txt' => "Target supports Next Protocol Negotiation (NPN)"},
    'adh'           => {'txt' => "Target does not accept ADH ciphers"},
    'null'          => {'txt' => "Target does not accept NULL ciphers"},
    'export'        => {'txt' => "Target does not accept EXPORT ciphers"},
    'rc4_cipher'    => {'txt' => "Target does not accept RC4 ciphers"},
    'closure'       => {'txt' => "Target understands TLS closure alerts"},
    'fallback'      => {'txt' => "Target supports fallback from TLSv1.1"},
    'order'         => {'txt' => "Target honors client's cipher order"},
    'ism'           => {'txt' => "Target is ISM compliant (ciphers only)"},
    'pci'           => {'txt' => "Target is PCI compliant (ciphers only)"},
    'fips'          => {'txt' => "Target is FIPS-140 compliant"},
#   'nsab'          => {'txt' => "Target is NSA Suite B compliant"},
    'tr-02102'      => {'txt' => "Target is TR-02102-2 compliant"},
    'tr-03116+'     => {'txt' => "Target is strict TR-03116-4 compliant"},
    'tr-03116-'     => {'txt' => "Target is  lazy  TR-03116-4 compliant"},
    'bsi-tr-02102+' => {'txt' => "Target is strict BSI TR-02102-2 compliant"},
    'bsi-tr-02102-' => {'txt' => "Target is  lazy  BSI TR-02102-2 compliant"},
    'bsi-tr-03116+' => {'txt' => "Target is strict BSI TR-03116-4 compliant"},
    'bsi-tr-03116-' => {'txt' => "Target is  lazy  BSI TR-03116-4 compliant"},
    'rfc7525'       => {'txt' => "Target is RFC 7525 compliant"},
    'resumption'    => {'txt' => "Target supports Resumption"},
    'renegotiation' => {'txt' => "Target supports Secure Renegotiation"},
    'pfs_cipher'    => {'txt' => "Target supports PFS (selected cipher)"},
    'pfs_cipherall' => {'txt' => "Target supports PFS (all ciphers)"},
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

my %check_size = (  # length and count data
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
    'cnt_ciphers'   => {'txt' => "Offered ciphers count"},          # <> 0
    'cnt_totals'    => {'txt' => "Total number of checked ciphers"},
    #------------------+-----------------------------------------------------
# TODO: cnt_ciphers, len_chain, cnt_chaindepth
); # %check_size

my %check_http = (  # HTTP vs. HTTPS data
    # score are absolute values here, they are set to 100 if attribute is found
    # key must have prefix (hsts|sts); see $cfg{'regex'}->{'cmd-http'}
    #------------------+-----------------------------------------------------
    'sts_maxage0d'  => {'txt' => "STS max-age not set"},             # very weak
    'sts_maxage1d'  => {'txt' => "STS max-age less than one day"},   # weak
    'sts_maxage1m'  => {'txt' => "STS max-age less than one month"}, # low
    'sts_maxage1y'  => {'txt' => "STS max-age less than one year"},  # medium
    'sts_maxagexy'  => {'txt' => "STS max-age more than one year"},  # high
    'hsts_sts'      => {'txt' => "Target sends STS header"},
    'sts_maxage'    => {'txt' => "Target sends STS header with proper max-age"},
    'sts_subdom'    => {'txt' => "Target sends STS header with includeSubdomain"},
    'hsts_is301'    => {'txt' => "Target redirects with status code 301"}, # RFC6797 requirement
    'hsts_is30x'    => {'txt' => "Target redirects not with 30x status code"}, # other than 301, 304
    'hsts_fqdn'     => {'txt' => "Target redirect matches given host"},
    'http_https'    => {'txt' => "Target redirects HTTP to HTTPS"},
    'hsts_location' => {'txt' => "Target sends STS and no Location header"},
    'hsts_refresh'  => {'txt' => "Target sends STS and no Refresh header"},
    'hsts_redirect' => {'txt' => "Target redirects HTTP without STS header"},
    'hsts_ip'       => {'txt' => "Target does not send STS header for IP"},
    'pkp_pins'      => {'txt' => "Target sends Public Key Pins header"},
    #------------------+-----------------------------------------------------
); # %check_http

# now construct %checks from %check_* and set 'typ'
foreach $key (keys %check_conn) { $checks{$key}->{txt} = $check_conn{$key}->{txt}; $checks{$key}->{typ} = 'connection'; }
foreach $key (keys %check_cert) { $checks{$key}->{txt} = $check_cert{$key}->{txt}; $checks{$key}->{typ} = 'certificate'; }
foreach $key (keys %check_dest) { $checks{$key}->{txt} = $check_dest{$key}->{txt}; $checks{$key}->{typ} = 'destination'; }
foreach $key (keys %check_size) { $checks{$key}->{txt} = $check_size{$key}->{txt}; $checks{$key}->{typ} = 'sizes'; }
foreach $key (keys %check_http) { $checks{$key}->{txt} = $check_http{$key}->{txt}; $checks{$key}->{typ} = 'https'; }
# more data added to %checks after defining %cfg, see below

our %data_oid = ( # TODO: nothing YET IMPLEMENTED except for EV
        # TODO: generate this table using Net::SSLeay functions like:
        #   Net::SSLeay::OBJ_nid2ln(),  Net::SSLeay::OBJ_ln2nid()
        #   Net::SSLeay::OBJ_nid2sn(),  Net::SSLeay::OBJ_sn2nid(),
        #   Net::SSLeay::OBJ_nid2obj(), Net::SSLeay::OBJ_obj2nid(),
        #   Net::SSLeay::OBJ_txt2obj(), Net::SSLeay::OBJ_txt2nid(),
        #   Net::SSLeay::OBJ_obj2txt(),
        # all constants and values are defined in openssl/crypto/objects/obj_dat.h
        #   print "nid ". Net::SSLeay::OBJ_txt2nid("CN"); # --> 13
        #   print "Nam ". Net::SSLeay::OBJ_obj2txt( Net::SSLeay::OBJ_txt2obj("1.3.6.1.5.5.7.3.3"), 0); # --> Code Signing
        #   print "nam ". Net::SSLeay::OBJ_obj2txt( Net::SSLeay::OBJ_txt2obj("CN"), 0); # --> commonName
        #   print "oid ". Net::SSLeay::OBJ_obj2txt( Net::SSLeay::OBJ_txt2obj("CN"), 1); # --> 2.5.4.3
        #   print "OID ". Net::SSLeay::OBJ_obj2txt( Net::SSLeay::OBJ_nid2obj( 13 ), 1); # --> 2.5.4.3
        # we should use NIDs to generate the hash, as all other strings are
        # case sensitive. get NIDs with:
        #   grep NID_ openssl/crypto/objects/objects.h | awk '{print $3}' | sort -n
        # so we can loop from 0..180 (or 300 if checks are possible)
        # see also: http://www.zytrax.com/books/ldap/apa/oid.html
        #
        # wir koennen dann einen Parser fuer OIDs bauen:
        #   loop ueber OID und dabei immer .N vom Ende wegnehmen und rest mit OBJ_obj2txt() ausgeben
        #   # 1.3.6.1.4 -->  "" . identified-organization . dot . iana . Private
        #   # 2.5.29.32 -->  "" . directory services (X.500) . id-ce . X509v3 Certificate Policies

#   '1.3.6.1'                   => {iso(1) org(3) dod(6) iana(1)}
    '1.3.6.1'                   => {'txt' => "Internet OID"},
    '1.3.6.1.5.5.7.1.1'         => {'txt' => "Authority Information Access"}, # authorityInfoAccess
    '1.3.6.1.5.5.7.1.12'        => {'txt' => STR_UNDEF},
    '1.3.6.1.5.5.7.1.14'        => {'txt' => "Proxy Certification Information"},
    '1.3.6.1.5.5.7.3.1'         => {'txt' => "Server Authentication"},
    '1.3.6.1.5.5.7.3.2'         => {'txt' => "Client Authentication"},
    '1.3.6.1.5.5.7.3.3'         => {'txt' => "Code Signing"},
    '1.3.6.1.5.5.7.3.4'         => {'txt' => "Email Protection"},
    '1.3.6.1.5.5.7.3.5'         => {'txt' => "IPSec end system"},
    '1.3.6.1.5.5.7.3.6'         => {'txt' => "IPSec tunnel"},
    '1.3.6.1.5.5.7.3.7'         => {'txt' => "IPSec user"},
    '1.3.6.1.5.5.7.3.8'         => {'txt' => "Timestamping"},
    '1.3.6.1.4.1.11129.2.5.1'   => {'txt' => STR_UNDEF},    # Certificate Policy?
    '1.3.6.1.4.1.14370.1.6'     => {'txt' => STR_UNDEF},    # Certificate Policy?
    '1.3.6.1.4.1.311.10.3.3'    => {'txt' => "Microsoft Server Gated Crypto"},
    '1.3.6.1.4.1.311.10.11'     => {'txt' => "Microsoft Server: EV additional Attributes"},
    '1.3.6.1.4.1.311.10.11.11'  => {'txt' => "Microsoft Server: EV ??friendly name??"},
    '1.3.6.1.4.1.311.10.11.83'  => {'txt' => "Microsoft Server: EV ??root program??"},
    '1.3.6.1.4.1.4146.1.10'     => {'txt' => STR_UNDEF},    # Certificate Policy?
    '2.16.840.1.113730.4.1'     => {'txt' => "Netscape SGC"},
    '1.2.840.113549.1.1.1'      => {'txt' => "SubjectPublicKeyInfo"}, # ???
    # EV: OIDs used in EV Certificates
    '2.5.4.10'                  => {'txt' => "EV Certificate: subject:organizationName"},
    '2.5.4.11'                  => {'txt' => "EV Certificate: subject:organizationalUnitName"},
    '2.5.4.15'                  => {'txt' => "EV Certificate: subject:businessCategory"},
    '2.5.4.3'                   => {'txt' => "EV Certificate: subject:commonName"}, # or SubjectAlternativeName:dNSName
    # EV: Jurisdiction of Incorporation or Registration
    '1.3.6.1.4.1.311.60.2.1.1'  => {'txt' => "EV Certificate: subject:jurisdictionOfIncorporationLocalityName"},
    '1.3.6.1.4.1.311.60.2.1.2'  => {'txt' => "EV Certificate: subject:jurisdictionOfIncorporationStateOrProvinceName"},
    '1.3.6.1.4.1.311.60.2.1.3'  => {'txt' => "EV Certificate: subject:jurisdictionOfIncorporationCountryName"},
    '2.5.4.5'                   => {'txt' => "EV Certificate: subject:serialNumber"},
    # EV: Physical Address of Place of Business
    '2.5.4.6'                   => {'txt' => "EV Certificate: subject:countryName"},
    '2.5.4.7'                   => {'txt' => "EV Certificate: subject:localityName"},
    '2.5.4.8'                   => {'txt' => "EV Certificate: subject:stateOrProvinceName"},
    '2.5.4.9'                   => {'txt' => "EV Certificate: subject:streetAddress"},
    '2.5.4.17'                  => {'txt' => "EV Certificate: subject:postalCode"},
    # EV: Compliance with European Union Qualified Certificates Standard In addition, RFC 3739
    '1.3.6.1.4.1.311.60.2.1'    => {'txt' => "EV Certificate: qcStatements:qcStatement:statementId"},
    # EV: others
    '1.3.6.1.4.1.311.60.1.1'    => {'txt' => "EV Certificate: ??fake root??"},
    '2.5.29.32.0'               => {'txt' => "EV Certificate: subject:anyPolicy"},
    '2.5.29.35'                 => {'txt' => "EV Certificate: subject:authorityKeyIdentifier"}, # Authority key id
    '2.5.29.37'                 => {'txt' => "EV Certificate: subject:extendedKeyUsage"}, # Extended key usage
    '0.9.2342.19200300.100.1.25'=> {'txt' => "EV Certificate: subject:domainComponent"},
    # others
    '2.5.4.4'                   => {'txt' => "subject:surname"},
    '2.5.4.12'                  => {'txt' => "subject:title"},
    '2.5.4.41'                  => {'txt' => "subject:name"},
    '2.5.4.42'                  => {'txt' => "subject:givenName"},
    '2.5.4.43'                  => {'txt' => "subject:intials"},
    '2.5.4.44'                  => {'txt' => "subject:generationQualifier"},
    '2.5.4.46'                  => {'txt' => "subject:dnQualifier"},
    '2.5.29.14'                 => {'txt' => "subject:subjectKeyIdentifier"}, # Subject key id
    '2.5.29.15'                 => {'txt' => "subject:keyUsage"},             # Key usage
    '2.5.29.17'                 => {'txt' => "subject:subjectAlternateName"}, # Subject alternative name
    '2.5.29.19'                 => {'txt' => "subject:basicConstraints"},     # Basic constraints
    '2.5.29.31'                 => {'txt' => "subject:crlDistributionPoints"},# CRL distribution points
    '2.5.29.32'                 => {'txt' => "subject:certificatePolicies"},  # Certificate Policies
    '2.16.840.1.113733.1.7.23.6'=> {'txt' => STR_UNDEF},    # Certificate Policy?
    '2.16.840.1.113733.1.7.48.1'=> {'txt' => STR_UNDEF},    #  ''
    '2.16.840.1.113733.1.7.54'  => {'txt' => STR_UNDEF},    #  ''
    '0.9.2342.19200300.100.1.3' => {'txt' => "subject:mail"},
); # %data_oid
$data_oid{$_}->{val} = "<<check error>>" foreach (keys %data_oid);

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
    'ocsp'          => "OCSP supported",
    'hassslv2'      => "No SSLv2",
    'hassslv3'      => "No SSLv3",
    'hastls10'      => "TLSv1",
    'hastls11'      => "TLSv1.1",
    'hastls12'      => "TLSv1.2",
    'hastls13'      => "TLSv1.3",
    'hasalpn'       => "Supports ALPN",
    'npn'           => "Supports NPN",
    'adh'           => "No ADH ciphers",
    'edh'           => "EDH ciphers",
    'null'          => "No NULL ciphers",
    'export'        => "No EXPORT ciphers",
    'rc4_cipher'    => "No RC4 ciphers",
    'sgc'           => "SGC supported",
    'cps'           => "CPS supported",
    'crl'           => "CRL supported",
    'dv'            => "DV supported",
    'ev+'           => "EV supported (strict)",
    'ev-'           => "EV supported (lazy)",
    'ev-chars'      => "No invalid characters in extensions",
    'beast'         => "Safe to BEAST (cipher)",
    'breach'        => "Safe to BREACH",
    'crime'         => "Safe to CRIME",
    'time'          => "Safe to TIME",
    'freak'         => "Safe to FREAK",
    'heartbleed'    => "Safe to Heartbleed",
    'lucky13'       => "Safe to Lucky 13",
    'logjam'        => "Safe to Logjam",
    'poodle'        => "Safe to POODLE",
    'rc4'           => "Safe to RC4 attack",
    'sloth'         => "Safe to SLOTH",
    'scsv'          => "SCSV not supported",
    'constraints'   => "Basic Constraints is false",
    'modulus_size'  => "Modulus <16385 bits",
    'modulus_exp_size'=>"Modulus Eexponent <65537",
    'pub_encryption'=> "Public Key with Encryption",
    'pub_enc_known' => "Public Key Encryption known",
    'sig_encryption'=> "Private Key with Encryption",
    'sig_enc_known' => "Private Key Encryption known",
    'rfc6125_names' => "Names according RFC6125",
    'closure'       => "TLS closure alerts",
    'fallback'      => "Fallback from TLSv1.1",
    'zlib'          => "ZLIB extension",
    'lzo'           => "GnuTLS extension",
    'open_pgp'      => "OpenPGP extension",
    'order'         => "Client's cipher order",
    'ism'           => "ISM compliant",
    'pci'           => "PCI compliant",
    'pfs_cipher'    => "PFS (selected cipher)",
    'pfs_cipherall' => "PFS (all ciphers)",
    'fips'          => "FIPS-140 compliant",
#   'nsab'          => "NSA Suite B compliant",
    'tr-02102'      => "TR-02102-2 compliant",
    'tr-03116+'     => "TR-03116-4 compliant (strict)",
    'tr-03116-'     => "TR-03116-4 compliant (lazy)",
    'bsi-tr-02102+' => "BSI TR-02102-2 compliant (strict)",
    'bsi-tr-02102-' => "BSI TR-02102-2 compliant (lazy)",
    'bsi-tr-03116+' => "BSI TR-03116-4 compliant (strict)",
    'bsi-tr-03116-' => "BSI TR-03116-4 compliant (lazy)",
    'rfc7525'       => "RFC 7525 compliant",
    'resumption'    => "Resumption",
    'renegotiation' => "Renegotiation",     # NOTE used in %data and %check_dest
    'hsts_sts'      => "STS header",
    'sts_maxage'    => "STS long max-age",
    'sts_maxage0d'  => "STS max-age not set",
    'sts_maxage1d'  => "STS max-age < 1 day",
    'sts_maxage1m'  => "STS max-age < 1 month",
    'sts_maxage1y'  => "STS max-age < 1 year",
    'sts_maxagexy'  => "STS max-age < 1 year",
    'sts_subdom'    => "STS includeSubdomain",
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
    'protocols'     => "Protocols",
    'alpn'          => "ALPN",
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
    'selected'      => "Selected Cipher",
    'ciphers_openssl'   => "OpenSSL Ciphers",
    'dates'         => "Validity (date)",
    'before'        => "Valid since",
    'after'         => "Valid until",
    'tlsextdebug'   => "SSL Extensions (debug)",
    'tlsextensions' => "SSL Extensions",
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
    'ocsp_uri'      => "OCSP URL",
    'ocspid'        => "OCSP Hash",
    'subject_hash'  => "Subject Hash",
    'issuer_hash'   => "Issuer Hash",
    'fp_not_md5'    => "Fingerprint not MD5",
    'cert_type'     => "Certificate Type (bitmask)",
    'verify_hostname'   => "Hostname valid",
    'verify_altname'    => "AltNames valid",
    'fingerprint_hash'  => "Fingerprint Hash",
    'fingerprint_type'  => "Fingerprint Algorithm",
    'fingerprint_sha1'  => "Fingerprint SHA1",
    'fingerprint_md5'   => "Fingerprint  MD5",
    'fingerprint'       => "Fingerprint:",
    'https_protocols'   => "HTTPS Alternate-Protocol",
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
    'hsts_is301'    => "HTTP Status code is 301",
    'hsts_is30x'    => "HTTP Status code not 30x",
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

#our %cfg = # already defined above (just some values, complete setting here)
%cfg = (
    # FIXME: (10) { following will be removed when %cfg is defined in o-saft-cfg.pm
    'ARG0'          => $0,
    'ARGV'          => [@ARGV], # arguments passed on command line
    'RC-ARGV'       => [@rc_argv],   # arguments read from RC-FILE
    'RC-FILE'       => "./$me", # our RC-FILE
    # FIXME: (10) }

   # config. key        default   description
   #------------------+---------+----------------------------------------------
    'try'           => 0,       # 1: do not execute openssl, just show
    'exec'          => 0,       # 1: if +exec command used
    'trace'         => 0,       # 1: trace yeast, 2=trace Net::SSLeay and Net::SSLinfo also
    'traceME'       => 0,       # 1: trace yeast only, but no modules
                                # -1: trace modules only, but not yeast
    'traceARG'      => 0,       # 1: trace yeast's argument processing
    'traceCMD'      => 0,       # 1: trace command processing
    'traceKEY'      => 0,       # 1: (trace) print yeast's internal variable names
    'traceTIME'     => 0,       # 1: (trace) print additiona time for benchmarking
    'linux_debug'   => 0,       # passed to Net::SSLeay::linux_debug
    'verbose'       => 0,       # used for --v
    'warning'       => 1,       # 1: print warnings; 0: don't print warnings
    'proxyhost'     => "",      # FQDN or IP of proxy to be used
    'proxyport'     => 0,       # port for proxy
    'proxyauth'     => "",      # authentication string used for proxy
    'proxyuser'     => "",      # username for proxy authentication (Basic or Digest Auth)
    'proxypass'     => "",      # password for proxy authentication (Basic or Digest Auth)
    'starttls'      => "",      # use STARTTLS if not empty
                                # protocol to be used with STARTTLS; default: SMTP
                                # valid protocols: SMTP, IMAP, IMAP2, POP3, FTPS, LDAP, RDP, XMPP
    'starttlsDelay' => 0,       # STARTTLS: time to wait in seconds (to slow down the requests)
    'enabled'       => 0,       # 1: only print enabled ciphers
    'disabled'      => 0,       # 1: only print disabled ciphers
    'nolocal'       => 0,
    'experimental'  => 0,       # 1: use experimental functionality
    'ignore_no_conn'=> 0,       # 1: ignore warnings if connection fails, check target anyway
    'uselwp'        => 0,       # 1: use perls LWP module for HTTP checks # TODO: NOT YET IMPLEMENTED
    'forcesni'      => 0,       # 1: do not check if SNI seems to be supported by Net::SSLeay
    'usesni'        => 1,       # 0: do not make connection in SNI mode;
    'usedns'        => 1,       # 1: make DNS reverse lookup
    'usemx'         => 0,       # 1: make MX-Record DNS lookup
    'usehttp'       => 1,       # 1: make HTTP request
    'use_md5cipher' => 1,       # 0: do not use *-MD5 ciphers except for SSLv2 with +cipher
    'use_reconnect' => 1,       # 0: do not use -reconnect option for openssl
    'use_nextprot'  => 1,       # 0: do not use -nextprotoneg option for openssl
    'use_extdebug'  => 1,       # 0: do not use -tlsextdebug option for openssl
    'slowly'        => 0,       # passed to Net::SSLeay::slowly
    'sni_name'      => "1",     # name to be used for SNI mode connection; hostname if empty
                                # NOTE: default=1 as this is behaviour for Net::SSLinfo < 1.85
    'sclient_opt'   => "",      # argument or option passed to openssl s_client command
    'no_cert'       => 0,       # 0: get data from certificate; 1, 2, do not get data
    'no_cert_txt'   => "",      # change default text if no data from cert retrieved
    'ca_depth'      => undef,   # depth of peer certificate verification verification
    'ca_crl'        => undef,   # URL where to find CRL file
    'ca_file'       => undef,   # PEM format file with CAs
    'ca_path'       => undef,   # path to directory with PEM files for CAs
                                # see Net::SSLinfo why undef as default
    'ca_paths'      => [qw(/etc/ssl/certs /usr/lib/certs /System/Library/OpenSSL)],
                                # common paths to PEM files for CAs
    'ca_files'      => [qw(ca-certificates.crt certificates.crt certs.pem)],
                                # common PEM filenames for CAs
    'openssl_cnf'   => undef,   # full path with openssl's openssl.cnf
    'openssl_cnfs'  => [qw(/usr/lib/ssl/openssl.cnf /etc/ssl/openssl.cnf /System//Library/OpenSSL/openssl.cnf /usr/ssl/openssl.cnf)], # NOT YET USED
    'openssl_fips'  => undef,   # NOT YET USED
    'openssl_msg'   => "",      # '-msg': option needed for openssl versions older than 1.0.2 to get the dh_parameter
    'ignorecase'    => 1,       # 1: compare some strings case insensitive
    'shorttxt'      => 0,       # 1: use short label texts
    'version'       => [],      # contains the versions to be checked
    'versions'      =>          # all supported versions
                       # [reverse sort keys %prot], # do not use generic list 'cause the want special order
                       [qw(SSLv2 SSLv3 TLSv1 TLSv11 TLSv12 TLSv13 DTLSv09 DTLSv1 DTLSv11 DTLSv12 DTLSv13)],
    'DTLS_versions' => [qw(DTLSv09 DTLSv1 DTLSv11 DTLSv12 DTLSv13)],
                                # temporary list 'cause DTLS not supported by openssl (6/2015)
    'ssl_lazy'      => 0,       # 1: lazy check for available SSL protocol functionality
    'SSLv2'         => 1,       # 1: check this SSL version
    'SSLv3'         => 1,       # 1:   "
    'TLSv1'         => 1,       # 1:   "
    'TLSv11'        => 1,       # 1:   "
    'TLSv12'        => 1,       # 1:   "
    'TLSv13'        => 1,       # 1:   "
                                # NOTE: DTLS currently (6/2015) disabled by default 'cause not supported by openssl
    'DTLSv09'       => 0,       # 1:   "
    'DTLSv1'        => 0,       # 1:   "
    'DTLSv11'       => 0,       # 1:   "
    'DTLSv12'       => 0,       # 1:   "
    'DTLSv13'       => 0,       # 1:   "
    'TLS1FF'        => 0,       # dummy for future use
    'DTLSfamily'    => 0,       # dummy for future use
    'nullssl2'      => 0,       # 1: complain if SSLv2 enabled but no ciphers accepted
    'cipher'        => [],      # ciphers we got with --cipher=
    'cipherpattern' => "ALL:NULL:eNULL:aNULL:LOW:EXP", # openssl pattern for all ciphers
                                # TODO: must be same as in Net::SSLinfo or used from there
    'ciphers'       => [],      # contains all ciphers to be tested
    'cipherrange'   => 'rfc',   # the range to be used from 'cipherranges'
    'cipherranges'  => {        # constants for ciphers (NOTE: written as hex)
                    # Technical (perl) note for definition of these ranges:
                    # Each range is defined as a string like  key=>"2..5, c..f"
                    # instead of an array like  key=>[2..5, c..f]  which would
                    # result in  key=>[2 3 4 5 c d e f] .
                    # This expansion of the range is done at compile time  and 
                    # so will consume a huge amount of memory at runtime.
                    # Using a string instead of the expanded array reduces the
                    # memory footprint,  but requires use of  eval()  when the
                    # range is needed:  eval($cfg{cipherranges}->{rfc})
                    # Each string must be syntax for perl's range definition.
        'yeast'     => "",      # internal list, computed later ...
                                # push(@all, @{$_}[0]) foreach (values %cipher_names);
        'rfc'       =>          # constants for ciphers defined in various RFCs
                       "0x03000000 .. 0x030000FF, 0x0300C000 .. 0x0300C0FF,
                        0x0300CC00 .. 0x0300CCFF, 0x0300FE00 .. 0x0300FFFF,
                       ",
        'shifted'   =>          # constants for ciphers defined in various RFCs shifted with an offset of 64 (=0x40) Bytes
                       "0x03000100 .. 0x0300013F,
                        0x03000000 .. 0x030000FF, 0x0300C000 .. 0x0300C0FF,
                        0x0300CC00 .. 0x0300CCFF, 0x0300FE00 .. 0x0300FFFF,
                       ",
        'long'      =>          # more lazy list of constants for cipher
                       "0x03000000 .. 0x030000FF, 0x0300C000 .. 0x0300FFFF,
                       ",
        'huge'      =>          # huge range of constants for cipher
                       "0x03000000 .. 0x0300FFFF,
                       ",
        'safe'      =>          # safe full range of constants for cipher
                                # because some network stack (NIC) will crash for 0x033xxxxx
                       "0x03000000 .. 0x032FFFFF,
                       ",
        'full'      =>          # full range of constants for cipher
                       "0x03000000 .. 0x03FFFFFF,
                       ",
# TODO:                 0x03000000,   0x03FFFFFF,   # used as return by microsoft testserver and also by SSL-honeypot (US)
        'SSLv2'     =>          # constants for ciphers according RFC for SSLv2
                       "0x02000000,   0x02010080, 0x02020080, 0x02030080, 0x02040080,
                        0x02050080,   0x02060040, 0x02060140, 0x020700C0, 0x020701C0,
                        0x02FF0810,   0x02FF0800, 0x02FFFFFF,   # obsolete SSLv2 ciphers
                        0x03000000 .. 0x03000002, 0x03000007 .. 0x0300002C, 0x030000FF,
                        0x0300FEE0,   0x0300FEE1, 0x0300FEFE, 0x0300FEFF, # obsolete FIPS ciphers
# TODO:                 0x02000000,   0x02FFFFFF,   # increment even only
# TODO:                 0x03000000,   0x03FFFFFF,   # increment  odd only
                       ",
        'SSLv2_long'=>          # more lazy list of constants for ciphers for SSLv2
                       "0x02000000,   0x02010080, 0x02020080, 0x02030080, 0x02040080,
                        0x02050080,   0x02060040, 0x02060140, 0x020700C0, 0x020701C0,
                        0x02FF0810,   0x02FF0800, 0x02FFFFFF,
                        0x03000000 .. 0x0300002F, 0x030000FF,   # old SSLv3 ciphers
                        0x0300FEE0,   0x0300FEE1, 0x0300FEFE, 0x0300FEFF,
                       ",
    }, # cipherranges
    'ciphers-v'     => 0,       # as: openssl ciphers -v
    'ciphers-V'     => 0,       # as: openssl ciphers -V
    'do'            => [],      # the commands to be performed, any of commands
    'commands'      => [],      # contains all commands, constructed below
    'ignore-out'    => [],      # commands (output) to be ignored, see --no-cmd
                    # Results of these commands are not printed in output.
                    # Purpose is to avoid output of noicy commands  (like some
                    # +bsi*).  All data collections and checks are still done,
                    # just output of results is omitted.
                    # Technically these commands are not removed from cfg{do},
                    # but just skipped in printdata() and printchecks(), which
                    # makes implementation much easier.
    'cmd-intern'    => [        # add internal commands
                    # these have no key in %data or %checks
                        qw(
                         check cipher dump check_sni exec help info info--v http
                         quick list libversion sizes s_client version quit
                         sigkey bsi ev cipherraw cipher-dh
                        ),
                    # internal (debugging) commands
                      # qw(options cert_type),  # will be seen with +info--v only
                    # keys not used as command
                        qw(cn_nosni valid-years valid-months valid-days)
                       ],
    'cmd-experiment'=> [        # experimental commands
                        qw(sloth),
                       ],
    'cmd-NL'        => [        # commands which need NL when printed
                                # they should be available with +info --v only 
                        qw(certificate extensions pem pubkey sigdump text chain chain_verify)
                       ],
    'cmd-NOT_YET'   => [        # commands and checks NOT YET IMPLEMENTED
                        qw(zlib lzo open_pgp fallback closure order sgc scsv time),
                       ],
    'cmd-beast'     => [qw(beast)],                 # commands for +beast
    'cmd-crime'     => [qw(crime)],                 # commands for +crime
    'cmd-freak'     => [qw(freak)],                 # commands for +freak
    'cmd-lucky13'   => [qw(lucky13)],               # commands for +lucky13
    'cmd-http'      => [],      # commands for +http, computed below
    'cmd-hsts'      => [],      # commands for +hsts, computed below
    'cmd-info'      => [],      # commands for +info, simply anything from %data
    'cmd-info--v'   => [],      # commands for +info --v
    'cmd-check'     => [],      # commands for +check, simply anything from %checks
    'cmd-sizes'     => [],      # commands for +sizes
    'cmd-quick'     => [        # commands for +quick
                        qw(
                         selected cipher fingerprint_hash fp_not_md5 
                         sha2signature pub_encryption pub_enc_known email
                         serial subject dates verify expansion compression hostname
                         beast crime freak export rc4_cipher rc4 pfs_cipher crl
                         hassslv2 hassslv3 poodle sloth
                         resumption renegotiation tr-02102 bsi-tr-02102+ bsi-tr-02102- hsts_sts
                       )],
    'cmd-ev'        => [qw(cn subject altname dv ev ev- ev+ ev-chars)], # commands for +ev
    'cmd-bsi'       => [                            # commands for +bsi
                        qw(after dates crl rc4_cipher renegotiation
                           tr-02102            bsi-tr-02102+ bsi-tr-02102-
                           tr-03116+ tr-03116- bsi-tr-03116+ bsi-tr-03116-
                       )],
    'cmd-pfs'       => [qw(pfs_cipher pfs_cipherall session_random)],   # commands for +pfs
    'cmd-sni'       => [qw(sni hostname)],          # commands for +sni
    'cmd-sni--v'    => [qw(sni cn altname verify_altname verify_hostname hostname wildhost wildcard)],
    'cmd-vulns'     => [                            # commands for checking known vulnerabilities
                        qw(beast breach crime freak heartbleed logjam lucky13 poodle rc4 sloth time hassslv2 hassslv3 pfs_cipher session_random)
                       #qw(resumption renegotiation) # die auch?
                       ],
    'cmd-prots'     => [                            # commands for checking protocols
                        qw(hassslv2 hassslv3 hastls10 hastls11 hastls12 hastls13 hasalpn alpn npn session_protocol protocols https_protocols http_protocols https_svc http_svc)
                       ],
                    # need_* lists used to improve performance
    'need_cipher'   => [        # commands which need +cipher
                        qw(check beast crime time breach freak pfs_cipher pfs_cipherall rc4_cipher rc4 selected poodle logjam sloth cipher cipher-dh),
                        qw(tr-02102 bsi-tr-02102+ bsi-tr-02102- tr-03116+ tr-03116- bsi-tr-03116+ bsi-tr-03116-),
                        qw(hassslv2 hassslv3 hastls10 hastls11 hastls12 hastls13), # TODO: need simple check for protocols
                       ],
    'need_default'  => [        # commands which need selected cipher
                        qw(check cipher pfs_cipher selected),
                        qw(sslv3  tlsv1   tlsv10  tlsv11 tlsv12),
                                # following checks may cause errors because
                                # missing functionality (i.e in openssl) # 10/2015
                        qw(sslv2  tlsv13  dtlsv09 dtlvs1 dtlsv11 dtlsv12 dtlsv13)
                       ],
    'need_checkssl' => [        # commands which need checkssl() # TODO: needs to be verified
                        qw(check beast crime time breach freak pfs_cipher pfs_cipherall rc4_cipher rc4 selected ev+ ev-),
                        qw(tr-02102 bsi-tr-02102+ bsi-tr-02102- tr-03116+ tr-03116- bsi-tr-03116+ bsi-tr-03116- rfc7525 rfc6125_names),
                       ],
    'data_hex'      => [        # data values which are in hex values
                                # used in conjunction with --format=hex
                                # not usefull in this list: serial extension
                        qw(
                         fingerprint fingerprint_hash fingerprint_sha1 fingerprint_md5
                         sigkey_value pubkey_value modulus
                         master_key session_id session_ticket
                       )],      # fingerprint is special, see _ishexdata()
    'opt-v'         => 0,       # 1 when option -v was given
    'opt-V'         => 0,       # 1 when option -V was given
    'format'        => "",      # empty means some slightly adapted values (no \s\n)
    'formats'       => [qw(csv html json ssv tab xml fullxml raw hex 0x esc)],
    'out_header'    => 0,       # print header lines in output
    'out_score'     => 0,       # print scoring; default for +check
    'tmplib'        => "/tmp/yeast-openssl/",   # temp. directory for openssl and its libraries
    'pass_options'  => "",      # options to be passeed thru to other programs
    'mx_domains'    => [],      # list of mx-domain:port to be processed
    'hosts'         => [],      # list of host:port to be processed
    'host'          => "",      # currently scanned host
    'ip'            => "",      # currently scanned host's IP (machine readable format)
    'IP'            => "",      # currently scanned host's IP (human readable, doted octed)
    'rhost'         => "",      # currently scanned host's reverse resolved name
    'DNS'           => "",      # currently scanned host's other IPs and names (DNS aliases)
    'port'          => 443,     # port for currently used connections
    'timeout'       => 2,       # default timeout in seconds for connections
                                # NOTE that some servers do not connect SSL within this time
                                #      this may result in ciphers marked as  "not supported"
                                #      it's recommended to set timeout to 3 or higher, which
                                #      results in a performance bottleneck, obviously
    'sslhello' => {    # configurations for TCP SSL protocol (mainly used in Net::SSLhello)
        'timeout'   => 2,       # timeout to receive ssl-answer
        'retry'     => 2,       # number of retry when timeout
        'maxciphers'=> 32,      # number of ciphers sent in SSL3/TLS Client-Hello
        'useecc'    => 1,       # 1: use supported elliptic curves
        'useecpoint'=> 1,       # 1: use ec_point_formats extension
        'usereneg'  => 0,       # 1: secure renegotiation
        'double_reneg'  => 0,   # 0: do not send reneg_info extension if the cipher_spec already includes SCSV
                                #    "TLS_EMPTY_RENEGOTIATION_INFO_SCSV" {0x00, 0xFF}
        'nodatanocipher'=> 1,   # 1: do not abort testing next cipher for some TLS intolerant Servers 'NoData or Timeout Equals to No Cipher'
    },
    'legacy'        => "simple",
    'legacys'       => [qw(cnark sslaudit sslcipher ssldiagnos sslscan ssltest
                        ssltest-g sslyze testsslserver thcsslcheck openssl
                        simple full compact quick key)],
                       # SSLAudit, THCSSLCheck, TestSSLServer are converted using lc()
    'showhost'      => 0,       # 1: prefix printed line with hostname
    'usr-args'      => [],      # list of all arguments --usr* (to be used in o-saft-usr.pm)
   #------------------+---------+----------------------------------------------
   #------------------+--------------------------------------------------------
    'regex' => {
        # First some basic RegEx used later on, either in following RegEx or
        # as $cfg{'regex'}->{...}  itself.
        '_or-'      => '[\+_-]',
                       # tools use _ or - as separator character; + used in openssl
        'ADHorDHA'  => '(?:A(?:NON[_-])?DH|DH(?:A|[_-]ANON))[_-]',
                       # Anonymous DH has various acronyms:
                       #     ADH, ANON_DH, DHA, DH-ANON, DH_Anon, ...
        'RC4orARC4' => '(?:ARC(?:4|FOUR)|RC4)',
                       # RC4 has other names due to copyright problems:
                       #     ARC4, ARCFOUR, RC4
        '3DESorCBC3'=> '(?:3DES(?:[_-]EDE)[_-]CBC|DES[_-]CBC3)',
                       # Tripple DES is used as 3DES-CBC, 3DES-EDE-CBC, or DES-CBC3
        'DESor3DES' => '(?:[_-]3DES|DES[_-]_192)',
                       # Tripple DES is used as 3DES or DES_192
        'DHEorEDH'  => '(?:DHE|EDH)[_-]',
                       # DHE and EDH are 2 acronyms for the same thing
        'EC-DSA'    => 'EC(?:DHE|EDH)[_-]ECDSA',
        'EC-RSA'    => 'EC(?:DHE|EDH)[_-]RSA',
                       # ECDHE-RSA or ECDHE-ECDSA
        'EC'        => 'EC(?:DHE|EDH)[_-]',
        'EXPORT'    => 'EXP(?:ORT)?(?:40|56|1024)?[_-]',
                       # EXP, EXPORT, EXPORT40, EXP1024, EXPORT1024, ...
        'FRZorFZA'  => '(?:FORTEZZA|FRZ|FZA)[_-]',
                       # FORTEZZA has abbreviations FZA and FRZ
                       # unsure about FORTEZZA_KEA
        'SHA2'      => 'sha(2|224|256|384|512)',
                       # any SHA2, just sha2 is too lazy
        'SSLorTLS'  => '^(?:SSL[23]?|TLS[12]?|PCT1?)[_-]',
                       # Numerous protocol prefixes are in use:
                       #     PTC, PCT1, SSL, SSL2, SSL3, TLS, TLS1, TLS2,
        'aliases'   => '(?:(?:DHE|DH[_-]ANON|DSS|RAS|STANDARD)[_-]|EXPORT_NONE?[_-]?XPORT|STRONG|UNENCRYPTED)',
                       # various variants for aliases to select cipher groups
        'compression'   =>'(?:DEFLATE|LZO)',    # if compression available
        'nocompression' =>'(?:NONE|NULL|^\s*$)',# if no compression available
        'encryption'    =>'(?:encryption|ecPublicKey)', # anything containing this string
        'encryption_ok' =>'(?:(?:(?:(?:md[245]|ripemd160|sha(?:1|224|256|384|512))with)?[rd]saencryption)|id-ecPublicKey)',
                       # well known strings to identify signature and public key encryption
                       # rsaencryption, dsaencryption, md[245]withrsaencryption, 
                       # ripemd160withrsa shaXXXwithrsaencryption
                       # id-ecPublicKey
        'encryption_no' =>'(?:rsa(?:ssapss)?|sha1withrsa|dsawithsha1?|dsa_with_sha256)',
                       # rsa, rsassapss, sha1withrsa, dsawithsha*, dsa_with_sha256
        'isIP'          => '(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)',
        'isDNS'         => '(?:[a-z0-9.-]+)',
        'isIDN'         => '(?:xn--)',
        'leftwild'      => '^\*(?:[a-z0-9.-]+)',
        'doublewild'    => '(?:[a-z0-9.-]+\*[a-z0-9-]+\*)', # x*x or x*.x*
        'invalidwild'   => '(?:\.\*\.)',            # no .*.
        'invalidIDN'    => '(?:xn--[a-z0-9-]*\*)',  # no * right of xn--

        # RegEx containing pattern to identify vulnerable ciphers
            #
            # In a perfect (perl) world we can use negative lokups like
            #     (ABC)(?!XYZ)
            # which means: contains `ABC' but not `XYZ' where `XYZ' could be
            # to the right or left of `ABC'.
            # But in real world some perl implementations fail to match such
            # pattern correctly. Hence we use two pattern:  one for positive
            # match and second for the negative (not) match. Both patterns
            # must be used programatically.
            # Key 'TYPE' must match and key 'notTYPE' must not match.
        # The following RegEx define what is "vulnerable":
        'BEAST'     => '^(?:SSL[23]?|TLS[12]|PCT1?[_-])?(?:ARC(?:4|FOUR)|RC4)',
#       'BREACH'    => '^(?:SSL[23]?|TLS[12]|PCT1?[_-])?',
        'FREAK'     => '^(?:SSL[23]?)?(?:EXP(?:ORT)?(?:40|56|1024)?[_-])',
                       # EXP? is same as regex{EXPORT} above
        'notCRIME'  => '(?:NONE|NULL|^\s*$)',   # same as nocompression (see above)
#       'TIME'      => '^(?:SSL[23]?|TLS[12]|PCT1?[_-])?',
        'Lucky13'   => '^(?:SSL[23]?|TLS[12]|PCT1?[_-])?.*?[_-]CBC',
        'Logjam'    => 'EXP(?:ORT)?(?:40|56|1024)?[_-]',    # match against cipher
                       # Logjam is same as regex{EXPORT} above
        'SLOTH'     => '(?:(EXP(?:ORT)?|NULL).*MD5$|EC(?:DHE|EDH)[_-]ECDSA[_-].*(?:MD5|SHA)$)',
        # The following RegEx define what is "not vulnerable":
        'PFS'       => '^(?:(?:SSLv?3|TLSv?1(?:[12])?|PCT1?)[_-])?((?:EC)?DHE|EDH)[_-]',

        'TR-02102'  => '(?:DHE|EDH)[_-](?:PSK|(?:EC)?(?:[DR]S[AS]))[_-]',
                       # ECDHE_ECDSA | ECDHE_RSA | DHE_DSS | DHE_RSA
                       # ECDHE_ECRSA, ECDHE_ECDSS or DHE_DSA does not exist, hence lazy regex above
        'notTR-02102'     => '[_-]SHA$',
                       # ciphers with SHA1 hash are not allowed
        'TR-02102-noPFS'  => '(?:EC)?DH)[_-](?:EC)?(?:[DR]S[AS])[_-]',
                       # if PFS not possible, see TR-02102-2 3.2.1
        'TR-03116+' => 'EC(?:DHE|EDH)[_-](?:PSK|(?:EC)?(?:[DR]S[AS]))[_-]AES128[_-](?:GCM[_-])?SHA256',
        'TR-03116-' => 'EC(?:DHE|EDH)[_-](?:PSK|(?:EC)?(?:[DR]S[AS]))[_-]AES(?:128|256)[_-](?:GCM[_-])?SHA(?:256|384)',
                       # in strict mode only:
                       #  ECDHE-ECDSA-AES128.*SHA256 ECDHE-RSA-AES128.*SHA256 RSA-PSK-AES128-SHA256 ECDHE-PSK-AES128-SHA256
                       # in lazy mode (for curiosity) we also allow:
                       #  ECDHE-ECDSA-AES256.*SHA256 ECDHE-RSA-AES256.*SHA256
                       #  ECDHE-ECDSA-AES256.*SHA384 ECDHE-RSA-AES256.*SHA384
        'notTR-03116'     => '(?:PSK[_-]AES256|[_-]SHA$)',
                       # NOTE: for curiosity again, notTR-03116 is for strict mode only
        'RFC7525'   => 'EC(?:DHE|EDH)[_-](?:PSK|(?:EC)?(?:[DR]S[AS]))[_-]AES128[_-](?:GCM[_-])?SHA256',
        '1.3.6.1.5.5.7.1.1'  =>  '(?:1\.3\.6\.1\.5\.5\.7\.1\.1|authorityInfoAccess)',
        'NSA-B'     =>'(?:ECD(?:H|SA).*?AES.*?GCM.*?SHA(?:256|384|512))',

        # Regex containing pattern for compliance checks
        # The following RegEx define what is "not compliant":
        'notISM'    => '(?:NULL|A(?:NON[_-])?DH|DH(?:A|[_-]ANON)[_-]|(?:^DES|[_-]DES)[_-]CBC[_-]|MD5|RC)',
        'notPCI'    => '(?:NULL|(?:A(?:NON[_-])?DH|DH(?:A|[_-]ANON)|(?:^DES|[_-]DES)[_-]CBC|EXP(?:ORT)?(?:40|56|1024)?)[_-])',
        'notFIPS-140'=>'(?:(?:ARC(?:4|FOUR)|RC4)|MD5|IDEA)',
        'FIPS-140'  => '(?:(?:3DES(?:[_-]EDE)[_-]CBC|DES[_-]CBC3)|AES)', # these are compiant

        # Regex for checking EV-SSL
        # they should matching:   /key=value/other-key=other-value
        '2.5.4.10'  => '(?:2\.5\.4\.10|organizationName|O)',
        '2.5.4.11'  => '(?:2\.5\.4\.1?|organizationalUnitName|OU)',
        '2.5.4.15'  => '(?:2\.5\.4\.15|businessCategory)',
        '2.5.4.3'   => '(?:2\.5\.4\.3|commonName|CN)',
        '2.5.4.5'   => '(?:2\.5\.4\.5|serialNumber)',
        '2.5.4.6'   => '(?:2\.5\.4\.6|countryName|C)',
        '2.5.4.7'   => '(?:2\.5\.4\.7|localityName|L)',
        '2.5.4.8'   => '(?:2\.5\.4\.8|stateOrProvinceName|SP|ST)', # TODO: is ST a bug?
        '2.5.4.9'   => '(?:2\.5\.4\.9|street(?:Address)?)', # '/street=' is very lazy
        '2.5.4.17'  => '(?:2\.5\.4\.17|postalCode)',
#       '?.?.?.?'   => '(?:?\.?\.?\.?|domainComponent|DC)',
#       '?.?.?.?'   => '(?:?\.?\.?\.?|surname|SN)',
#       '?.?.?.?'   => '(?:?\.?\.?\.?|givenName|GN)',
#       '?.?.?.?'   => '(?:?\.?\.?\.?|pseudonym)',
#       '?.?.?.?'   => '(?:?\.?\.?\.?|initiala)',
#       '?.?.?.?'   => '(?:?\.?\.?\.?|title)',
        '1.3.6.1.4.1.311.60.2.1.1' => '(?:1\.3\.6\.1\.4\.1\.311\.60\.2\.1\.1|jurisdictionOfIncorporationLocalityName)',
        '1.3.6.1.4.1.311.60.2.1.2' => '(?:1\.3\.6\.1\.4\.1\.311\.60\.2\.1\.2|jurisdictionOfIncorporationStateOrProvinceName)',
        '1.3.6.1.4.1.311.60.2.1.3' => '(?:1\.3\.6\.1\.4\.1\.311\.60\.2\.1\.3|jurisdictionOfIncorporationCountryName)',

        'EV-chars'  => '[a-zA-Z0-9,./:= @?+\'()-]',         # valid characters in EV definitions
        'notEV-chars'=>'[^a-zA-Z0-9,./:= @?+\'()-]',        # not valid characters in EV definitions
        'EV-empty'  => '^(?:n\/a|(?:in|not )valid)\s*$',    # empty string, or "invalid" or "not valid"

        # Regex for matching commands
        'cmd-http'  => '^h?(?:ttps?|sts)_',     # match keys for HTTP
        'cmd-hsts'  => '^h?sts',                # match keys for (H)STS
        'cmd-sizes' => '^(?:cnt|len)_',         # match keys for length, sizes etc.
        'cmd-intern'=> '^(?:cn_nosni|valid-(?:year|month|day)s)', # internal data only, no command

        # Regex for matching SSL protocol keys in %data and %checks
        'SSLprot'   => '^(SSL|D?TLS)v[0-9]',    # match keys SSLv2, TLSv1, ...

    }, # regex
   #------------------+--------------------------------------------------------
    'ourstr' => {
        # regex to match strings of our own output, see OUTPUT in o-saft-man.pm
        # first all that match a line at beginning:
        'error'     => qr(^\*\*ERR),            # see STR_ERROR
        'warning'   => qr(^\*\*WARN),           # see STR_WARN
        'hint'      => qr(^\*\*Hint),           # see STR_HINT
        'dbx'       => qr(^#dbx#),              # see STR_DBX
        'headline'  => qr(^={1,3} ),            # headlines
        'keyline'   => qr(^#\[),                # dataline prefixed with key
        'verbose'   => qr(^#[^[]),              # verbose output
        # matches somewhere in the line:
        'undef'     => qr(\<\<undef),           # see STR_UNDEF
        'yeast'     => qr(\<\<.*?\>\>),         # additional informations
        'na'        => qr(N\/A),                # N/A
        'yes'       => qr(:\s*yes),             # good check result; # TODO: : needs to be $text{separator}
        'no'        => qr(:\s*no ),             # bad check result
    }, # ourstr
   #------------------+--------------------------------------------------------
    'compliance' => {           # description of RegEx above for compliance checks
        'TR-02102'  => "no RC4, only eclipic curve, only SHA256 or SHA384, need CRL and AIA, no wildcards, and verifications ...",
        'TR-03116'  => "TLSv1.2, only ECDSA, RSA or PSK ciphers, only eclipic curve, only SHA224 or SHA256, need OCSP-Stapling CRL and AIA, no wildcards, and verifications ...",
        'ISM'       => "no NULL cipher, no Anonymous Auth, no single DES, no MD5, no RC ciphers",
        'PCI'       => "no NULL cipher, no Anonymous Auth, no single DES, no Export encryption, DH > 1023",
        'FIPS-140'  => "must be TLSv1 or 3DES or AES, no IDEA, no RC4, no MD5",
        'FIPS-140-2'=> "-- NOT YET IMPLEMENTED --",      # TODO:
        'RFC7525'   => "TLS 1.2; AES with GCM; ECDHE and SHA256 or SHA384; HSTS",
        #
        # NIST SP800-52 recommendations for clients (best first):
        #   TLS_DHE_DSS_WITH_AES_256_CBC_SHA
        #   TLS_DHE_RSA_WITH_AES_256_CBC_SHA
        #   TLS_RSA_WITH_AES_256_CBC_SHA
        #   TLS_DH_DSS_WITH_AES_256_CBC_SHA
        #   TLS_DH_RSA_WITH_AES_256_CBC_SHA
        #   TLS_DHE_DSS_WITH_AES_128_CBC_SHA
        #   TLS_DHE_RSA_WITH_AES_128_CBC_SHA
        #   TLS_RSA_WITH_AES_128_CBC_SHA
        #   TLS_DH_DSS_WITH_AES_128_CBC_SHA
        #   TLS_DH_RSA_WITH_AES_128_CBC_SHA
        #   TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
        #   TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
        #   TLS_RSA_WITH_3DES_EDE_CBC_SHA
        #   TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA
        #   TLS_DH_RSA_WITH_3DES_EDE_CBC
        #   TLS_RSA_WITH_RC4_128_SHA2
        #
        # NIST SP800-52 recommendations for server (best first):
        #    same as above except TLS_RSA_WITH_RC4_128_SHA2
        #
        # Supported by (most) browsers (see SSL_comp_report2011.pdf):
        #    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384  (IE8 only)
        #    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA*
        #    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA*
        #    TLS_DHE_RSA_WITH_AES_256_CBC_SHA
        #    TLS_DHE_RSA_WITH_AES_128_CBC_SHA
        #    TLS_RSA_WITH_RC4_128_SHA
        #    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
        #
        # NIST SP800-57 recommendations for key management (part 1):
        'NSA-B'     => "must be AES with CTR or GCM; ECDSA or ECDH and SHA256 or SHA512",
    },
    'sig_algorithms' => [       # signature algorithms; (2016) not yet used
        qw(
           dsaEncryption dsaEncryption-old dsaWithSHA dsaWithSHA1 dsa_With_SHA256
           ecdsa-with-SHA256
           md2WithRSAEncryption    md4WithRSAEncryption  md5WithRSAEncryption
           None   ripemd160WithRSA rsa  rsaEncryption    rsassapss
           shaWithRSAEncryption	   sha1WithRSAEncryption sha1WithRSA
           sha224WithRSAEncryption sha256WithRSAEncryption
           sha384WithRSAEncryption sha512WithRSAEncryption
        ),
           "rsassapss (invalid pss parameters)"
    ],
    'sig_algorithm_common' => [ # most common signature algorithms; (2016) not yet used
        qw(None ecdsa-with-SHA256
           sha1WithRSAEncryption   sha256WithRSAEncryption
           sha384WithRSAEncryption sha512WithRSAEncryption
        )
    ],
    'openssl_option_map' => {   # map our internal option to openssl option; used our Net:SSL*
        # will be initialized from %prot
     },
    'openssl_version_map' => {  # map our internal option to openssl version (hex value); used our Net:SSL*
        # will be initialized from %prot
     },
    'done' => {                 # internal administration
        'hosts'     => 0,
        'dbxfile'   => 0,
        'rc-file'   => 0,
        'init_all'  => 0,
        'arg_cmds'  => [],      # contains all commands given as argument
         # all following need to be reset for each host
        'ciphers_all'   => 0,
        'ciphers_get'   => 0,
        'checkciphers'  => 0,   # not used, as it's called multiple times
        'checkdefault'  => 0,
        'check02102'=> 0,
        'check03116'=> 0,
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
        'checkdv'   => 0,
        'checkev'   => 0,
        'check_dh'  => 0,
     },
    'extension' => {            # TLS extensions
        '00000'     => "renegotiation info length",     # 0x0000 ??
        '00001'     => "renegotiation length",          # 0x0001 ??
        '00010'     => "elliptic curves",    # 0x000a length=4
        '00011'     => "EC point formats",   # 0x000b length=2
        '00015'     => "heartbeat",          # 0x000f length=1
        '00035'     => "session ticket",     # 0x0023 length=0
        '13172'     => "next protocol",      # 0x3374 length=NNN
        '65281'     => "renegotiation info", # 0xff01 length=1
    },
); # %cfg

$cfg{'openssl_option_map'}->{$_}  = $prot{$_}->{'opt'} foreach (keys %prot); # copy to %cfg
$cfg{'openssl_version_map'}->{$_} = $prot{$_}->{'hex'} foreach (keys %prot); # copy to %cfg

## construct list for special commands: 'cmd-*'
## -------------------------------------
my $old = "";
my $rex = join("|", @{$cfg{'versions'}});   # these are data only, not commands
foreach $key (sort {uc($a) cmp uc($b)} keys %data, keys %checks, @{$cfg{'cmd-intern'}}) {
    next if ($key eq $old); # unique
    $old = $key;
    push(@{$cfg{'commands'}},  $key) if ($key !~ m/^($rex)/);
    push(@{$cfg{'cmd-hsts'}},  $key) if ($key =~ m/$cfg{'regex'}->{'cmd-hsts'}/i);
    push(@{$cfg{'cmd-http'}},  $key) if ($key =~ m/$cfg{'regex'}->{'cmd-http'}/i);
    push(@{$cfg{'cmd-sizes'}}, $key) if ($key =~ m/$cfg{'regex'}->{'cmd-sizes'}/);
}

push(@{$cfg{'cmd-check'}}, $_) foreach (keys %checks);
push(@{$cfg{'cmd-info--v'}}, 'dump');       # more information
foreach $key (keys %data) {
    push(@{$cfg{'cmd-info--v'}}, $key);
    next if (_is_intern($key) > 0);         # ignore aliases
    next if ($key =~ m/^(ciphers)/   and $verbose == 0); # Client ciphers are less important
    next if ($key =~ m/^modulus$/    and $verbose == 0); # same values as 'pubkey_value'
    push(@{$cfg{'cmd-info'}},    $key);
}
push(@{$cfg{'cmd-info--v'}}, 'info--v');

_y_TIME("cfg}");

our %ciphers_desc = (   # description of following %ciphers table
    'head'          => [qw(  sec  ssl   enc  bits mac  auth  keyx   score  tags)],
                            # abbreviations used by openssl:
                            # SSLv2, SSLv3, TLSv1, TLSv1.1, TLSv1.2
                            # Kx=  key exchange (DH is diffie-hellman)
                            # Au=  authentication
                            # Enc= encryption with bit size
                            # Mac= mac encryption algorithm
    'text'          => [ # full description of each column in 'ciphers' below
        'Security',         # LOW, MEDIUM, HIGH as reported by openssl 0.9.8 .. 1.0.1h
                            # WEAK as reported by openssl 0.9.8 as EXPORT
                            # weak unqualified by openssl or know vulnerable
                            # NOTE: weak includes NONE (no security at all)
                            #
                            # all following informations as reported by openssl 0.9.8 .. 1.0.1h
        'SSL/TLS',          # Protocol Version:
                            # SSLv2, SSLv3, TLSv1, TLSv11, TLSv12, TLSv13, DTLS0.9, DTLS1.0, PCT
                            # NOTE: all SSLv3 are also TLSv1, TLSv11, TLSv12
                            # (cross-checked with sslaudit.ini)
        'Encryption Algorithm', # None, AES, AESCCM, AESGCM, CAMELLIA, DES, 3DES, FZA, IDEA, RC4, RC2, SEED
        'Key Size',         # in bits
        'MAC Algorithm',    # MD5, SHA1, SHA256, SHA384, AEAD
        'Authentication',   # None, DSS, RSA, ECDH, ECDSA, KRB5, PSK
        'Key Exchange',     # DH, ECDH, ECDH/ECDSA, RSA, KRB5, PSK, SRP
                            # last column is a : separated list (only export from openssl)
                            # different versions of openssl report  ECDH or ECDH/ECDSA
        'score',            # score value as defined in sslaudit.ini (0, 20, 80, 100)
                            # additionally following sores are used:
                            #  10: have been 100 in sslaudit.ini (HIGH  in openssl)
                            #   8: have been 80 in sslaudit.ini  (MDIUM in openssl)
                            #   3:                               (LOW   in openssl)
                            #   2: have been 20 in sslaudit.ini
                            #   1: assumed weak security
                            #  11: unknown, assumed weak security
                            #  81: unknown, assumed MEDIUM security
                            #  91: unknown, assumed HIGH security
                            #   0: all anon and NULL and <56 bit ciphers dispite above settings
        'tags',             # export  as reported by openssl 0.9.8 .. 1.0.1h
                            # OSX     on Mac OS X only
                            # :    (colon) is empty marker (need for other tools
        ],
); # %ciphers_desc
our %ciphers = (
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
 # FIXME: perl hashes may not have multiple keys (have them for SSLv2 and SSLv3)
        'ADH-AES128-SHA'        => [qw(  weak SSLv3 AES   128 SHA1 None  DH          0 :)],
        'ADH-AES256-SHA'        => [qw(  weak SSLv3 AES   256 SHA1 None  DH          0 :)],
        'ADH-DES-CBC3-SHA'      => [qw(  weak SSLv3 3DES  168 SHA1 None  DH          0 :)],
        'ADH-DES-CBC-SHA'       => [qw(  weak SSLv3 DES    56 SHA1 None  DH          0 :)],
        'ADH-RC4-MD5'           => [qw(  weak SSLv3 RC4   128 MD5  None  DH          0 :)], # openssl: MEDIUM
        'ADH-SEED-SHA'          => [qw(  weak SSLv3 SEED  128 SHA1 None  DH          0 OSX)], # openssl: MEDIUM
        #
        'AECDH-AES128-SHA'      => [qw(  weak SSLv3 AES   128 SHA1 None  ECDH       11 :)],
        'AECDH-AES256-SHA'      => [qw(  weak SSLv3 AES   256 SHA1 None  ECDH       11 :)],
        'AECDH-DES-CBC3-SHA'    => [qw(  weak SSLv3 3DES  168 SHA1 None  ECDH       11 :)],
        'AECDH-NULL-SHA'        => [qw(  weak SSLv3 None    0 SHA1 None  ECDH        0 :)],
        'AECDH-RC4-SHA'         => [qw(  weak SSLv3 RC4   128 SHA1 None  ECDH       11 :)], # openssl: MEDIUM
        'AES128-SHA'            => [qw(  HIGH SSLv3 AES   128 SHA1 RSA   RSA        80 :)],
        'AES256-SHA'            => [qw(  HIGH SSLv3 AES   256 SHA1 RSA   RSA       100 :)],
        'DES-CBC3-MD5'          => [qw(  HIGH SSLv2 3DES  168 MD5  RSA   RSA        80 :)],
        'DES-CBC3-SHA'          => [qw(  HIGH SSLv3 3DES  168 SHA1 RSA   RSA        80 :)],
        'DES-CBC3-SHA'          => [qw(  HIGH SSLv2 3DES  168 SHA1 RSA   RSA        80 :)],
        'DES-CBC-MD5'           => [qw(   LOW SSLv2 DES    56 MD5  RSA   RSA        20 :)],
        'DES-CBC-SHA'           => [qw(   LOW SSLv3 DES    56 SHA1 RSA   RSA        20 :)],
        'DES-CBC-SHA'           => [qw(   LOW SSLv2 DES    56 SHA1 RSA   RSA        20 :)],
        'DES-CFB-M1'            => [qw(  weak SSLv2 DES    64 MD5  RSA   RSA        20 :)],
        'DH-DSS-AES128-SHA'     => [qw(medium -?-   AES   128 SHA1 DSS   DH         81 :)],
        'DH-DSS-AES256-SHA'     => [qw(medium -?-   AES   256 SHA1 DSS   DH         81 :)],
        'DH-RSA-AES128-SHA'     => [qw(medium -?-   AES   128 SHA1 RSA   DH         81 :)],
        'DH-RSA-AES256-SHA'     => [qw(medium -?-   AES   256 SHA1 RSA   DH         81 :)],
        'DHE-DSS-AES128-SHA'    => [qw(  HIGH SSLv3 AES   128 SHA1 DSS   DH         80 :)],
        'DHE-DSS-AES256-SHA'    => [qw(  HIGH SSLv3 AES   256 SHA1 DSS   DH        100 :)],
        'DHE-DSS-RC4-SHA'       => [qw(  weak SSLv3 RC4   128 SHA1 DSS   DH         80 :)], # FIXME: degrade this also?
        'DHE-DSS-SEED-SHA'      => [qw(MEDIUM SSLv3 SEED  128 SHA1 DSS   DH         81 OSX)],
        'DHE-RSA-AES128-SHA'    => [qw(  HIGH SSLv3 AES   128 SHA1 RSA   DH         80 :)],
        'DHE-RSA-AES256-SHA'    => [qw(  HIGH SSLv3 AES   256 SHA1 RSA   DH        100 :)],
        'DHE-RSA-SEED-SHA'      => [qw(MEDIUM SSLv3 SEED  128 SHA1 RSA   DH         81 OSX)],
        'ECDH-ECDSA-AES128-SHA' => [qw(  HIGH SSLv3 AES   128 SHA1 ECDH  ECDH/ECDSA 91 :)],
        'ECDH-ECDSA-AES256-SHA' => [qw(  HIGH SSLv3 AES   256 SHA1 ECDH  ECDH/ECDSA 91 :)],
        'ECDH-ECDSA-DES-CBC3-SHA'=>[qw(  HIGH SSLv3 3DES  168 SHA1 ECDH  ECDH/ECDSA 11 :)],
        'ECDH-ECDSA-RC4-SHA'    => [qw(  weak SSLv3 RC4   128 SHA1 ECDH  ECDH/ECDSA 81 :)], #openssl: MEDIUM
        'ECDH-ECDSA-NULL-SHA'   => [qw(  weak SSLv3 None    0 SHA1 ECDH  ECDH/ECDSA  0 :)],
        'ECDH-RSA-AES128-SHA'   => [qw(  HIGH SSLv3 AES   128 SHA1 ECDH  ECDH/RSA   11 :)],
        'ECDH-RSA-AES256-SHA'   => [qw(  HIGH SSLv3 AES   256 SHA1 ECDH  ECDH/RSA   11 :)],
        'ECDH-RSA-DES-CBC3-SHA' => [qw(  HIGH SSLv3 3DES  168 SHA1 ECDH  ECDH/RSA   11 :)],
        'ECDH-RSA-RC4-SHA'      => [qw(  weak SSLv3 RC4   128 SHA1 ECDH  ECDH/RSA   81 :)], #openssl: MEDIUM
        'ECDH-RSA-NULL-SHA'     => [qw(  weak SSLv3 None    0 SHA1 ECDH  ECDH/RSA    0 :)],
        'ECDHE-ECDSA-AES128-SHA'=> [qw(  HIGH SSLv3 AES   128 SHA1 ECDSA ECDH       11 :)],
        'ECDHE-ECDSA-AES256-SHA'=> [qw(  HIGH SSLv3 AES   256 SHA1 ECDSA ECDH       11 :)],
        'ECDHE-ECDSA-DES-CBC3-SHA'=> [qw(HIGH SSLv3 3DES  168 SHA1 ECDSA ECDH       11 :)],
        'ECDHE-ECDSA-NULL-SHA'  => [qw(  weak SSLv3 None    0 SHA1 ECDSA ECDH        0 :)],
        'ECDHE-ECDSA-RC4-SHA'   => [qw(  weak SSLv3 RC4   128 SHA1 ECDSA ECDH       81 :)], #openssl: MEDIUM
        'ECDHE-RSA-AES128-SHA'  => [qw(  HIGH SSLv3 AES   128 SHA1 RSA   ECDH       11 :)],
        'ECDHE-RSA-AES256-SHA'  => [qw(  HIGH SSLv3 AES   256 SHA1 RSA   ECDH       11 :)],
        'ECDHE-RSA-DES-CBC3-SHA'=> [qw(  HIGH SSLv3 3DES  168 SHA1 RSA   ECDH       11 :)],
        'ECDHE-RSA-RC4-SHA'     => [qw(  weak SSLv3 RC4   128 SHA1 RSA   ECDH       81 :)], #openssl: MEDIUM
        'ECDHE-RSA-NULL-SHA'    => [qw(  weak SSLv3 None    0 SHA1 RSA   ECDH        0 :)],
        'EDH-DSS-DES-CBC3-SHA'  => [qw(  HIGH SSLv3 3DES  168 SHA1 DSS   DH         80 :)],
        'EDH-DSS-DES-CBC-SHA'   => [qw(   LOW SSLv3 DES    56 SHA1 DSS   DH          1 :)],
        'EDH-RSA-DES-CBC3-SHA'  => [qw(  HIGH SSLv3 3DES  168 SHA1 RSA   DH         80 :)],
        'EDH-RSA-DES-CBC-SHA'   => [qw(   LOW SSLv3 DES    56 SHA1 RSA   DH         20 :)],
        'EXP-ADH-DES-CBC-SHA'   => [qw(  weak SSLv3 DES    40 SHA1 None  DH(512)     0 export)],
        'EXP-ADH-RC4-MD5'       => [qw(  weak SSLv3 RC4    40 MD5  None  DH(512)     0 export)],
        'EXP-DES-CBC-SHA'       => [qw(  WEAK SSLv3 DES    40 SHA1 RSA   RSA(512)    2 export)],
        'EXP-EDH-DSS-DES-CBC-SHA'=>[qw(  WEAK SSLv3 DES    40 SHA1 DSS   DH(512)     2 export)],
        'EXP-EDH-RSA-DES-CBC-SHA'=>[qw(  WEAK SSLv3 DES    40 SHA1 RSA   DH(512)     2 export)],
        'EXP-RC2-CBC-MD5'       => [qw(  WEAK SSLv2 RC2    40 MD5  RSA   RSA(512)    2 export)],
        'EXP-RC2-CBC-MD5'       => [qw(  WEAK SSLv3 RC2    40 MD5  RSA   RSA(512)    2 export)],
        'EXP-RC4-MD5'           => [qw(  WEAK SSLv2 RC4    40 MD5  RSA   RSA(512)    2 export)],
        'EXP-RC4-MD5'           => [qw(  WEAK SSLv3 RC4    40 MD5  RSA   RSA(512)    2 export)],
        'EXP-RC4-64-MD5'        => [qw(  weak SSLv3 RC4    64 MD5  DSS   RSA         2 :)], # (from RSA BSAFE SSL-C)
        'EXP-EDH-DSS-RC4-56-SHA'=> [qw(  WEAK SSLv3 RC4    56 SHA  DSS   DHE         2 :)], # (from RSA BSAFE SSL-C)
        'EXP1024-DES-CBC-SHA'   => [qw(  WEAK SSLv3 DES    56 SHA1 RSA   RSA(1024)   2 export)],
        'EXP1024-DHE-DSS-RC4-SHA'=>[qw(  WEAK SSLv3 RC4    56 SHA1 DSS   DH(1024)    2 export)],
        'EXP1024-DHE-DSS-DES-CBC-SHA' => [qw(WEAK SSLv3 DES 56 SHA1 DSS  DH(1024)    2 export)],
        'EXP1024-RC2-CBC-MD5'   => [qw(  WEAK SSLv3 RC2    56 MD5  RSA   RSA(1024)   1 export)],
        'EXP1024-RC4-MD5'       => [qw(  WEAK SSLv3 RC4    56 MD5  RSA   RSA(1024)   1 export)],
        'EXP1024-RC4-SHA'       => [qw(  WEAK SSLv3 RC4    56 SHA1 RSA   RSA(1024)   2 export)],
        'IDEA-CBC-MD5'          => [qw(MEDIUM SSLv2 IDEA  128 MD5  RSA   RSA        80 :)],
        'IDEA-CBC-SHA'          => [qw(MEDIUM SSLv2 IDEA  128 SHA1 RSA   RSA        80 :)],
        'NULL'                  => [qw(  weak SSLv2 None    0 -?-  None  -?-         0 :)], # openssl SSLeay testing
        'NULL-MD5'              => [qw(  weak SSLv2 None    0 MD5  RSA   RSA(512)    0 :)],
        'NULL-MD5'              => [qw(  weak SSLv3 None    0 MD5  RSA   RSA(512)    0 export)], # FIXME: same hash key as before
        'NULL-SHA'              => [qw(  weak SSLv3 None    0 SHA1 RSA   RSA         0 :)],
        'RSA-PSK-AES128-CBC-SHA'=> [qw(  HIGH SSLv3 AES   128 SHA1 AES   RSAPSK    100 :)], 
#       'RSA-PSK-AES128-SHA'    => [qw(  HIGH SSLv3 AES   128 SHA1 AES   RSAPSK    100 :)], # same as RSA-PSK-AES128-CBC-SHA
        'RSA-PSK-AES256-CBC-SHA'=> [qw(  HIGH SSLv3 RSA   256 SHA1 AES   RSAPSK    100 :)],
#       'RSA-PSK-AES256-SHA    '=> [qw(  HIGH SSLv3 RSA   256 SHA1 AES   RSAPSK    100 :)], # same as RSA-PSK-AES128-CBC-SHA
        'RSA-PSK-3DES-EDE-CBC-SHA'=>[qw( HIGH SSLv3 3DES  168 SHA1 RSA   RSAPSK     90 :)],
#       'RSA-PSK-3DES-SHA'      => [qw(  HIGH SSLv3 3DES  168 SHA1 RSA   RSAPSK     90 :)], # same as RSA-PSK-3DES-EDE-CBC-SHA
        'PSK-3DES-EDE-CBC-SHA'  => [qw(  HIGH SSLv3 3DES  168 SHA1 PSK   PSK        90 :)],
        'PSK-AES128-CBC-SHA'    => [qw(  HIGH SSLv3 AES   128 SHA1 PSK   PSK       100 :)],
        'PSK-AES256-CBC-SHA'    => [qw(  HIGH SSLv3 AES   256 SHA1 PSK   PSK       100 :)],
        'RSA-PSK-RC4-SHA'       => [qw(MEDIUM SSLv3 RC4   128 SHA1 RSA   RSAPSK     80 :)],
        'PSK-RC4-SHA'           => [qw(MEDIUM SSLv3 RC4   128 SHA1 PSK   PSK        80 :)],
        'RC2-CBC-MD5'           => [qw(MEDIUM SSLv2 RC2   128 MD5  RSA   RSA        11 :)],
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
        'GOST94-GOST89-GOST89'  => [qw(  -?-  SSLv3 GOST89 256 GOST89  GOST94 VKO    1 :)],
        'GOST2001-GOST89-GOST89'=> [qw(  -?-  SSLv3 GOST89 256 GOST89  GOST01 VKO    1 :)],
        'GOST94-NULL-GOST94'    => [qw(  -?-  SSLv3 None     0 GOST94  GOST94 VKO    1 :)],
        'GOST2001-NULL-GOST94'  => [qw(  -?-  SSLv3 None     0 GOST94  GOST01 VKO    1 :)],
        #-----------------------------+------+-----+----+----+----+-----+--------+----+--------,

        # from openssl-1.0.1c
        #!#-----------------------------------+------+-----+------+---+------+-----+--------+----+--------,
        #!# 'head'                      => [qw(  sec  ssl   enc   bits mac    auth  keyx    score tags)],
        #!#-----------------------------------+------+-----+------+---+------+-----+--------+----+--------,
        'SRP-AES-128-CBC-SHA'           => [qw(  HIGH SSLv3 AES    128 SHA1   None  SRP        91 :)], # openssl: HIGH
        'SRP-AES-256-CBC-SHA'           => [qw(  HIGH SSLv3 AES    256 SHA1   None  SRP        91 :)], # openssl: HIGH
        'SRP-DSS-3DES-EDE-CBC-SHA'      => [qw(  HIGH SSLv3 3DES   168 SHA1   DSS   SRP        91 :)],
        'SRP-DSS-AES-128-CBC-SHA'       => [qw(  HIGH SSLv3 AES    128 SHA1   DSS   SRP        91 :)],
        'SRP-DSS-AES-256-CBC-SHA'       => [qw(  HIGH SSLv3 AES    256 SHA1   DSS   SRP        91 :)],
        'SRP-RSA-3DES-EDE-CBC-SHA'      => [qw(  HIGH SSLv3 3DES   168 SHA1   RSA   SRP        91 :)],
        'SRP-RSA-AES-128-CBC-SHA'       => [qw(  HIGH SSLv3 AES    128 SHA1   RSA   SRP        91 :)],
        'SRP-RSA-AES-256-CBC-SHA'       => [qw(  HIGH SSLv3 AES    256 SHA1   RSA   SRP        91 :)],
        'SRP-3DES-EDE-CBC-SHA'          => [qw(  HIGH SSLv3 3DES   168 SHA1   None  SRP        91 :)], # openssl: HIGH
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
        #!#-----------------------------------+------+-----+------+---+------+-----+--------+----+--------,

        # from https://tools.ietf.org/html/draft-ietf-tls-chacha20-poly1305-04 (16. Dec 2016)
        'PSK-CHACHA20-POLY1305-SHA256'  => [qw( HIGH TLSv12 ChaCha20-Poly1305 256 AEAD PSK   PSK   1 :)],
        'ECDHE-PSK-CHACHA20-POLY1305-SHA256'=> [qw( HIGH TLSv12 ChaCha20-Poly1305 256 AEAD ECDH  PSK   1 :)],
        'DHE-PSK-CHACHA20-POLY1305-SHA256'  => [qw( HIGH TLSv12 ChaCha20-Poly1305 256 AEAD DH    PSK   1 :)],
        'RSA-PSK-CHACHA20-POLY1305-SHA256'  => [qw( HIGH TLSv12 ChaCha20-Poly1305 256 AEAD RSA   PSK   1 :)],

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
        'KRB5-DES-CBC3-MD5'             => [qw(  HIGH SSLv3 3DES   168 MD5    KRB5  KRB5      100 :)],
        'KRB5-DES-CBC3-SHA'             => [qw(  HIGH SSLv3 3DES   168 SHA1   KRB5  KRB5      100 :)],
        'KRB5-IDEA-CBC-MD5'             => [qw(MEDIUM SSLv3 IDEA   128 MD5    KRB5  KRB5       80 :)],
        'KRB5-IDEA-CBC-SHA'             => [qw(MEDIUM SSLv3 IDEA   128 SHA1   KRB5  KRB5       80 :)],
        'KRB5-RC4-MD5'                  => [qw(  weak SSLv3 RC4    128 MD5    KRB5  KRB5        0 :)],
        'KRB5-RC4-SHA'                  => [qw(  weak SSLv3 RC4    128 SHA1   KRB5  KRB5        0 :)],
        'KRB5-DES-CBC-MD5'              => [qw(   LOW SSLv3 DES     56 MD5    KRB5  KRB5       20 :)],
        'KRB5-DES-CBC-SHA'              => [qw(   LOW SSLv3 DES     56 SHA1   KRB5  KRB5       20 :)],
        'EXP-KRB5-DES-CBC-MD5'          => [qw(  WEAK SSLv3 DES     40 MD5    KRB5  KRB5        0 export)],
        'EXP-KRB5-DES-CBC-SHA'          => [qw(  WEAK SSLv3 DES     40 SHA1   KRB5  KRB5        0 export)],
        'EXP-KRB5-RC2-CBC-MD5'          => [qw(  WEAK SSLv3 RC2     40 MD5    KRB5  KRB5        0 export)],
        'EXP-KRB5-RC2-CBC-SHA'          => [qw(  WEAK SSLv3 RC2     40 SHA1   KRB5  KRB5        0 export)],
        'EXP-KRB5-RC4-MD5'              => [qw(  WEAK SSLv3 RC4     40 MD5    KRB5  KRB5        0 export)],
        'EXP-KRB5-RC4-SHA'              => [qw(  WEAK SSLv3 RC4     40 SHA1   KRB5  KRB5        0 export)],
        # from ssl/s3_lib.c
        'FZA-NULL-SHA'                  => [qw(  weak SSLv3 None     0 SHA1   KEA   FZA        11 :)],
        'FZA-FZA-SHA'                   => [qw(MEDIUM SSLv3 FZA      0 SHA1   KEA   FZA        81 :)],
        'FZA-RC4-SHA'                   => [qw(  WEAK SSLv3 RC4    128 SHA1   KEA   FZA        11 :)],
        'RSA-FIPS-3DES-EDE-SHA'         => [qw(  high SSLv3 3DES   168 SHA1 RSA_FIPS RSA_FIPS  99 :)],
        'RSA-FIPS-3DES-EDE-SHA'         => [qw(  high SSLv3 3DES   168 SHA1 RSA_FIPS RSA_FIPS  99 :)],
        'RSA-FIPS-DES-CBC-SHA'          => [qw(   low SSLv3 DES_CBC 56 SHA1 RSA_FIPS RSA_FIPS  20 :)],
        'RSA-FIPS-DES-CBC-SHA'          => [qw(   low SSLv3 DES_CBC 56 SHA1 RSA_FIPS RSA_FIPS  20 :)],

        # FIXME: all following
        'EXP-DH-DSS-DES-CBC-SHA'        => [qw( weak  SSLv3 DES    40 SHA1    DSS   DH(512)    0 export)],
        'EXP-DH-RSA-DES-CBC-SHA'        => [qw( weak  SSLv3 DES    40 SHA1    RSA   DH(512)    0 export)],
        'DH-DSS-DES-CBC-SHA'            => [qw(  low  SSLv3 DES    56 SHA1    DSS   DH         20 :)],
        'DH-RSA-DES-CBC-SHA'            => [qw(  low  SSLv3 DES    56 SHA1    RSA   DH         20 :)],
        'DH-DSS-DES-CBC3-SHA'           => [qw( high  SSLv3 3DES   168 SHA1   DSS   DH         80 :)],
        'DH-RSA-DES-CBC3-SHA'           => [qw( high  SSLv3 3DES   168 SHA1   RSA   DH         80 :)],
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
        'DHE-PSK-SHA'                   => [qw(   -?- -?-   -?-    -?- SHA1   PSK   DHE         1 :)],
        'RSA-PSK-SHA'                   => [qw(   -?- -?-   -?-    -?- SHA1   PSK   RSA         1 :)],
        'DHE-PSK-RC4-SHA'               => [qw(   -?- -?-   RC4    -?- SHA1   PSK   PSK         1 :)],
        'DHE-PSK-3DES-SHA'              => [qw(   -?- -?-   3DES   -?- SHA1   PSK   PSK         1 :)],
        'DHE-PSK-AES128-SHA'            => [qw(   -?- -?-   AES    128 SHA1   PSK   PSK         1 :)],
        'DHE-PSK-AES256-SHA'            => [qw(   -?- -?-   AES    256 SHA1   PSK   PSK         1 :)],
        'DHE-PSK-AES128-GCM-SHA256'     => [qw(   -?- -?-   AES    128 SHA256 PSK   PSK         1 :)],
        'DHE-PSK-AES256-GCM-SHA384'     => [qw(   -?- -?-   AES    256 SHA384 PSK   PSK         1 :)],
        'RSA-PSK-AES128-GCM-SHA256'     => [qw(   -?- -?-   AES    128 SHA256 PSK   PSK         1 :)],
        'RSA-PSK-AES256-GCM-SHA384'     => [qw(   -?- -?-   AES    256 SHA384 PSK   PSK         1 :)],
        'PSK-AES128-SHA256'             => [qw(   -?- -?-   AES    128 SHA256 PSK   PSK         1 :)],
        'PSK-AES256-SHA384'             => [qw(   -?- -?-   AES    256 SHA384 PSK   PSK         1 :)],
        'PSK-SHA256'                    => [qw(   -?- -?-   AES    -?- SHA256 PSK   PSK         1 :)],
        'PSK-SHA384'                    => [qw(   -?- -?-   AES    -?- SHA384 PSK   PSK         1 :)],
        'DHE-PSK-AES128-SHA256'         => [qw(   -?- -?-   AES    128 SHA256 PSK   PSK         1 :)],
        'DHE-PSK-AES256-SHA384'         => [qw(   -?- -?-   AES    256 SHA384 PSK   PSK         1 :)],
        'DHE-PSK-SHA256'                => [qw(   -?- -?-   AES    -?- SHA256 PSK   PSK         1 :)],
        'DHE-PSK-SHA384'                => [qw(   -?- -?-   AES    -?- SHA384 PSK   PSK         1 :)],
        'RSA-PSK-AES128-SHA256'         => [qw(   -?- -?-   AES    128 SHA256 PSK   PSK         1 :)],
        'RSA-PSK-AES256-SHA384'         => [qw(   -?- -?-   AES    256 SHA384 PSK   PSK         1 :)],
        'RSA-PSK-SHA256'                => [qw(   -?- -?-   AES    -?- SHA256 PSK   PSK         1 :)],
        'RSA-PSK-SHA384'                => [qw(   -?- -?-   AES    -?- SHA384 PSK   PSK         1 :)],

    # === openssl ===
    # above table (roughly) generated with:
    #   openssl ciphers -v ALL:eNULL:aNULL | sort \
    #   | awk '{e=$7;printf("\t%26s => [%s, %s, %s, %s, %s, %s, %s],\n",$1,$2,substr($5,5),substr($5,index($5,"(")+1),substr($6,5),substr($4,4),substr($3,4),e)}'
    # or better
    #   | awk '{q="'"'"'";a=sprintf("%s%c",$1,q);e=$7;printf("\t%c%-26s => [qw( -?-\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t13 :)],\n",q,a,$2,substr($5,5),substr($5,index($5,"(")+1),substr($6,5),substr($4,4),substr($3,4),e)}' # )
    # === openssl 0.9.8o ===
    # above table (roughly) generated with:
    #   openssl ciphers -v ALL:eNULL:aNULL | sort
    #
    # NOTE: some openssl (0.9.8o on Ubuntu 11.10) fail to list ciphers with
    #    openssl ciphers -ssl2 -v

); # %ciphers

our %cipher_names = (
    # ADH_DES_192_CBC_SHA      # alias: DH_anon_WITH_3DES_EDE_CBC_SHA
    # ADH_DES_40_CBC_SHA       # alias: DH_anon_EXPORT_WITH_DES40_CBC_SHA
    # ADH_DES_64_CBC_SHA       # alias: DH_anon_WITH_DES_CBC_SHA
    # ADH_RC4_40_MD5           # alias: DH_anon_EXPORT_WITH_RC4_40_MD5
    # DHE_RSA_WITH_AES_128_SHA # alias: DHE_RSA_WITH_AES_128_CBC_SHA
    # DHE_RSA_WITH_AES_256_SHA # alias: DHE_RSA_WITH_AES_256_CBC_SHA
    #
    #!#----------+-------------------------------------+--------------------------+
    #!# constant =>     cipher suite name               cipher suite value
    #!#----------+-------------------------------------+--------------------------+
    '0x0300001B' => [qw(ADH-DES-CBC3-SHA                ADH_DES_192_CBC_SHA)],
    '0x03000019' => [qw(EXP-ADH-DES-CBC-SHA             ADH_DES_40_CBC_SHA)],
    '0x0300001A' => [qw(ADH-DES-CBC-SHA                 ADH_DES_64_CBC_SHA)],
    '0x03000018' => [qw(ADH-RC4-MD5                     ADH_RC4_128_MD5)],
    '0x03000017' => [qw(EXP-ADH-RC4-MD5                 ADH_RC4_40_MD5)],
    '0x030000A6' => [qw(ADH-AES128-GCM-SHA256           ADH_WITH_AES_128_GCM_SHA256)],
    '0x03000034' => [qw(ADH-AES128-SHA                  ADH_WITH_AES_128_SHA)],
    '0x0300006C' => [qw(ADH-AES128-SHA256               ADH_WITH_AES_128_SHA256)],
    '0x030000A7' => [qw(ADH-AES256-GCM-SHA384           ADH_WITH_AES_256_GCM_SHA384)],
    '0x0300003A' => [qw(ADH-AES256-SHA                  ADH_WITH_AES_256_SHA)],
    '0x0300006D' => [qw(ADH-AES256-SHA256               ADH_WITH_AES_256_SHA256)],
    '0x03000046' => [qw(ADH-CAMELLIA128-SHA             ADH_WITH_CAMELLIA_128_CBC_SHA)],
    '0x03000089' => [qw(ADH-CAMELLIA256-SHA             ADH_WITH_CAMELLIA_256_CBC_SHA)],
    '0x030000BF' => [qw(ADH-CAMELLIA128-SHA256          ADH_WITH_CAMELLIA_128_CBC_SHA256)],
    '0x030000C5' => [qw(ADH-CAMELLIA256-SHA256          ADH_WITH_CAMELLIA_256_CBC_SHA256)],
    '0x0300009B' => [qw(ADH-SEED-SHA                    ADH_WITH_SEED_SHA)],
    '0x020700c0' => [qw(DES-CBC3-MD5                    DES_192_EDE3_CBC_WITH_MD5)],
    '0x020701c0' => [qw(DES-CBC3-SHA                    DES_192_EDE3_CBC_WITH_SHA)],
    '0x02060040' => [qw(DES-CBC-MD5                     DES_64_CBC_WITH_MD5)],
    '0x02060140' => [qw(DES-CBC-SHA                     DES_64_CBC_WITH_SHA)],
    '0x02ff0800' => [qw(DES-CFB-M1                      DES_64_CFB64_WITH_MD5_1)],
    '0x03000063' => [qw(EXP1024-DHE-DSS-DES-CBC-SHA     DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA)],
    '0x03000065' => [qw(EXP1024-DHE-DSS-RC4-SHA         DHE_DSS_EXPORT1024_WITH_RC4_56_SHA)],
    '0x030000A2' => [qw(DHE-DSS-AES128-GCM-SHA256       DHE_DSS_WITH_AES_128_GCM_SHA256)],
    '0x03000032' => [qw(DHE-DSS-AES128-SHA              DHE_DSS_WITH_AES_128_SHA)],
    '0x03000040' => [qw(DHE-DSS-AES128-SHA256           DHE_DSS_WITH_AES_128_SHA256)],
    '0x030000A3' => [qw(DHE-DSS-AES256-GCM-SHA384       DHE_DSS_WITH_AES_256_GCM_SHA384)],
    '0x03000038' => [qw(DHE-DSS-AES256-SHA              DHE_DSS_WITH_AES_256_SHA)],
    '0x0300006A' => [qw(DHE-DSS-AES256-SHA256           DHE_DSS_WITH_AES_256_SHA256)],
    '0x03000044' => [qw(DHE-DSS-CAMELLIA128-SHA         DHE_DSS_WITH_CAMELLIA_128_CBC_SHA)],
    '0x03000087' => [qw(DHE-DSS-CAMELLIA256-SHA         DHE_DSS_WITH_CAMELLIA_256_CBC_SHA)],
    '0x030000BD' => [qw(DHE-DSS-CAMELLIA128-SHA256      DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256)],
    '0x030000C3' => [qw(DHE-DSS-CAMELLIA256-SHA256      DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256)],
    '0x03000066' => [qw(DHE-DSS-RC4-SHA                 DHE_DSS_WITH_RC4_128_SHA)],
    '0x03000099' => [qw(DHE-DSS-SEED-SHA                DHE_DSS_WITH_SEED_SHA)],
    '0x0300009E' => [qw(DHE-RSA-AES128-GCM-SHA256       DHE_RSA_WITH_AES_128_GCM_SHA256)],
    '0x03000033' => [qw(DHE-RSA-AES128-SHA              DHE_RSA_WITH_AES_128_SHA)],
    '0x03000067' => [qw(DHE-RSA-AES128-SHA256           DHE_RSA_WITH_AES_128_SHA256)],
    '0x0300009F' => [qw(DHE-RSA-AES256-GCM-SHA384       DHE_RSA_WITH_AES_256_GCM_SHA384)],
    '0x03000039' => [qw(DHE-RSA-AES256-SHA              DHE_RSA_WITH_AES_256_SHA)],
    '0x0300006B' => [qw(DHE-RSA-AES256-SHA256           DHE_RSA_WITH_AES_256_SHA256)],
    '0x03000045' => [qw(DHE-RSA-CAMELLIA128-SHA         DHE_RSA_WITH_CAMELLIA_128_CBC_SHA)],
    '0x03000088' => [qw(DHE-RSA-CAMELLIA256-SHA         DHE_RSA_WITH_CAMELLIA_256_CBC_SHA)],
    '0x030000BE' => [qw(DHE-RSA-CAMELLIA128-SHA256      DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256)],
    '0x030000C4' => [qw(DHE-RSA-CAMELLIA256-SHA256      DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256)],
    '0x0300CC15' => [qw(DHE-RSA-CHACHA20-POLY1305-SHA256   DHE_RSA_WITH_CHACHA20_POLY1305_SHA256)],
    '0x0300CCAA' => [qw(DHE-RSA-CHACHA20-POLY1305-SHA256   DHE_RSA_WITH_CHACHA20_POLY1305_SHA256)], # see Note(c)
    '0x0300CCAB' => [qw(PSK-CHACHA20-POLY1305-SHA256    PSK_WITH_CHACHA20_POLY1305_SHA256)],
    '0x0300CCAC' => [qw(ECDHE-PSK-CHACHA20-POLY1305-SHA256 ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256)],
    '0x0300CCAD' => [qw(DHE-PSK-CHACHA20-POLY1305-SHA256   DHE_PSK_WITH_CHACHA20_POLY1305_SHA256)],
    '0x0300CCAE' => [qw(PSK-RSA-CHACHA20-POLY1305       RSA_PSK_WITH_CHACHA20_POLY1305_SHA256)],
    '0x0300009A' => [qw(DHE-RSA-SEED-SHA                DHE_RSA_WITH_SEED_SHA)],
    '0x030000BB' => [qw(DH-DSS-CAMELLIA128-SHA256       DH_DSS_WITH_CAMELLIA_128_CBC_SHA256)],
    '0x030000C1' => [qw(DH-DSS-CAMELLIA256-SHA256       DH_DSS_WITH_CAMELLIA_256_CBC_SHA256)],
    '0x0300000D' => [qw(DH-DSS-DES-CBC3-SHA             DH_DSS_DES_192_CBC3_SHA)],
    '0x0300000B' => [qw(EXP-DH-DSS-DES-CBC-SHA          DH_DSS_DES_40_CBC_SHA)],
    '0x0300000C' => [qw(DH-DSS-DES-CBC-SHA              DH_DSS_DES_64_CBC_SHA)],
    '0x030000A4' => [qw(DH-DSS-AES128-GCM-SHA256        DH_DSS_WITH_AES_128_GCM_SHA256)],
    '0x03000030' => [qw(DH-DSS-AES128-SHA               DH_DSS_WITH_AES_128_SHA)],
    '0x0300003E' => [qw(DH-DSS-AES128-SHA256            DH_DSS_WITH_AES_128_SHA256)],
    '0x030000A5' => [qw(DH-DSS-AES256-GCM-SHA384        DH_DSS_WITH_AES_256_GCM_SHA384)],
    '0x03000036' => [qw(DH-DSS-AES256-SHA               DH_DSS_WITH_AES_256_SHA)],
    '0x03000068' => [qw(DH-DSS-AES256-SHA256            DH_DSS_WITH_AES_256_SHA256)],
    '0x03000042' => [qw(DH-DSS-CAMELLIA128-SHA          DH_DSS_WITH_CAMELLIA_128_CBC_SHA)],
    '0x03000085' => [qw(DH-DSS-CAMELLIA256-SHA          DH_DSS_WITH_CAMELLIA_256_CBC_SHA)],
    '0x03000097' => [qw(DH-DSS-SEED-SHA                 DH_DSS_WITH_SEED_SHA)],
    '0x03000010' => [qw(DH-RSA-DES-CBC3-SHA             DH_RSA_DES_192_CBC3_SHA)],
    '0x0300000E' => [qw(EXP-DH-RSA-DES-CBC-SHA          DH_RSA_DES_40_CBC_SHA)],
    '0x0300000F' => [qw(DH-RSA-DES-CBC-SHA              DH_RSA_DES_64_CBC_SHA)],
    '0x030000A0' => [qw(DH-RSA-AES128-GCM-SHA256        DH_RSA_WITH_AES_128_GCM_SHA256)],
    '0x03000031' => [qw(DH-RSA-AES128-SHA               DH_RSA_WITH_AES_128_SHA)],
    '0x0300003F' => [qw(DH-RSA-AES128-SHA256            DH_RSA_WITH_AES_128_SHA256)],
    '0x030000A1' => [qw(DH-RSA-AES256-GCM-SHA384        DH_RSA_WITH_AES_256_GCM_SHA384)],
    '0x03000037' => [qw(DH-RSA-AES256-SHA               DH_RSA_WITH_AES_256_SHA)],
    '0x03000069' => [qw(DH-RSA-AES256-SHA256            DH_RSA_WITH_AES_256_SHA256)],
    '0x03000043' => [qw(DH-RSA-CAMELLIA128-SHA          DH_RSA_WITH_CAMELLIA_128_CBC_SHA)],
    '0x03000086' => [qw(DH-RSA-CAMELLIA256-SHA          DH_RSA_WITH_CAMELLIA_256_CBC_SHA)],
    '0x030000BC' => [qw(DH-RSA-CAMELLIA128-SHA256       DH_RSA_WITH_CAMELLIA_128_CBC_SHA256)],
    '0x030000C2' => [qw(DH-RSA-CAMELLIA256-SHA256       DH_RSA_WITH_CAMELLIA_256_CBC_SHA256)],
    '0x03000098' => [qw(DH-RSA-SEED-SHA                 DH_RSA_WITH_SEED_SHA)],
    '0x0300C009' => [qw(ECDHE-ECDSA-AES128-SHA          ECDHE_ECDSA_WITH_AES_128_CBC_SHA)],
    '0x0300C02B' => [qw(ECDHE-ECDSA-AES128-GCM-SHA256   ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)],
    '0x0300C023' => [qw(ECDHE-ECDSA-AES128-SHA256       ECDHE_ECDSA_WITH_AES_128_SHA256)],
    '0x0300C00A' => [qw(ECDHE-ECDSA-AES256-SHA          ECDHE_ECDSA_WITH_AES_256_CBC_SHA)],
    '0x0300C02C' => [qw(ECDHE-ECDSA-AES256-GCM-SHA384   ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)],
    '0x0300C024' => [qw(ECDHE-ECDSA-AES256-SHA384       ECDHE_ECDSA_WITH_AES_256_SHA384)],
    '0x03000072' => [qw(ECDHE-ECDSA-CAMELLIA128-SHA256  ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256)],
    '0x03000073' => [qw(ECDHE-ECDSA-CAMELLIA256-SHA384  ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384)],
    '0x0300CC14' => [qw(ECDHE-ECDSA-CHACHA20-POLY1305-SHA256 ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)],
    '0x0300CCA9' => [qw(ECDHE-ECDSA-CHACHA20-POLY1305-SHA256 ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)], # see Note(c)
    '0x0300C008' => [qw(ECDHE-ECDSA-DES-CBC3-SHA        ECDHE_ECDSA_WITH_DES_192_CBC3_SHA)],
    '0x0300C006' => [qw(ECDHE-ECDSA-NULL-SHA            ECDHE_ECDSA_WITH_NULL_SHA)],
    '0x0300C007' => [qw(ECDHE-ECDSA-RC4-SHA             ECDHE_ECDSA_WITH_RC4_128_SHA)],
    '0x0300C013' => [qw(ECDHE-RSA-AES128-SHA            ECDHE_RSA_WITH_AES_128_CBC_SHA)],
    '0x0300C02F' => [qw(ECDHE-RSA-AES128-GCM-SHA256     ECDHE_RSA_WITH_AES_128_GCM_SHA256)],
    '0x0300C027' => [qw(ECDHE-RSA-AES128-SHA256         ECDHE_RSA_WITH_AES_128_SHA256)],
    '0x0300C014' => [qw(ECDHE-RSA-AES256-SHA            ECDHE_RSA_WITH_AES_256_CBC_SHA)],
    '0x0300C030' => [qw(ECDHE-RSA-AES256-GCM-SHA384     ECDHE_RSA_WITH_AES_256_GCM_SHA384)],
    '0x0300C028' => [qw(ECDHE-RSA-AES256-SHA384         ECDHE_RSA_WITH_AES_256_SHA384)],
    '0x03000076' => [qw(ECDHE-RSA-CAMELLIA128-SHA256    ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256)],
    '0x03000077' => [qw(ECDHE-RSA-CAMELLIA256-SHA384    ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384)],
    '0x0300CC13' => [qw(ECDHE-RSA-CHACHA20-POLY1305-SHA256  ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)],
    '0x0300CCA8' => [qw(ECDHE-RSA-CHACHA20-POLY1305-SHA256  ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)], # see Note(c)
    '0x0300C012' => [qw(ECDHE-RSA-DES-CBC3-SHA          ECDHE_RSA_WITH_DES_192_CBC3_SHA)],
    '0x0300C010' => [qw(ECDHE-RSA-NULL-SHA              ECDHE_RSA_WITH_NULL_SHA)],
    '0x0300C011' => [qw(ECDHE-RSA-RC4-SHA               ECDHE_RSA_WITH_RC4_128_SHA)],
    '0x0300C004' => [qw(ECDH-ECDSA-AES128-SHA           ECDH_ECDSA_WITH_AES_128_CBC_SHA)],
    '0x0300C02D' => [qw(ECDH-ECDSA-AES128-GCM-SHA256    ECDH_ECDSA_WITH_AES_128_GCM_SHA256)],
    '0x0300C025' => [qw(ECDH-ECDSA-AES128-SHA256        ECDH_ECDSA_WITH_AES_128_SHA256)],
    '0x0300C005' => [qw(ECDH-ECDSA-AES256-SHA           ECDH_ECDSA_WITH_AES_256_CBC_SHA)],
    '0x0300C02E' => [qw(ECDH-ECDSA-AES256-GCM-SHA384    ECDH_ECDSA_WITH_AES_256_GCM_SHA384)],
    '0x0300C026' => [qw(ECDH-ECDSA-AES256-SHA384        ECDH_ECDSA_WITH_AES_256_SHA384)],
    '0x03000074' => [qw(ECDH-ECDSA-CAMELLIA128-SHA256   ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256)],
    '0x03000075' => [qw(ECDH-ECDSA-CAMELLIA256-SHA384   ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384)],
    '0x0300C003' => [qw(ECDH-ECDSA-DES-CBC3-SHA         ECDH_ECDSA_WITH_DES_192_CBC3_SHA)],
    '0x0300C001' => [qw(ECDH-ECDSA-NULL-SHA             ECDH_ECDSA_WITH_NULL_SHA)],
    '0x0300C002' => [qw(ECDH-ECDSA-RC4-SHA              ECDH_ECDSA_WITH_RC4_128_SHA)],
    '0x0300C00E' => [qw(ECDH-RSA-AES128-SHA             ECDH_RSA_WITH_AES_128_CBC_SHA)],
    '0x0300C031' => [qw(ECDH-RSA-AES128-GCM-SHA256      ECDH_RSA_WITH_AES_128_GCM_SHA256)],
    '0x0300C029' => [qw(ECDH-RSA-AES128-SHA256          ECDH_RSA_WITH_AES_128_SHA256)],
    '0x0300C00F' => [qw(ECDH-RSA-AES256-SHA             ECDH_RSA_WITH_AES_256_CBC_SHA)],
    '0x0300C032' => [qw(ECDH-RSA-AES256-GCM-SHA384      ECDH_RSA_WITH_AES_256_GCM_SHA384)],
    '0x0300C02A' => [qw(ECDH-RSA-AES256-SHA384          ECDH_RSA_WITH_AES_256_SHA384)],
    '0x03000078' => [qw(ECDH-RSA-CAMELLIA128-SHA256     ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256)],
    '0x03000079' => [qw(ECDH-RSA-CAMELLIA256-SHA384     ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384)],
    '0x0300C00D' => [qw(ECDH-RSA-DES-CBC3-SHA           ECDH_RSA_WITH_DES_192_CBC3_SHA)],
    '0x0300C00B' => [qw(ECDH-RSA-NULL-SHA               ECDH_RSA_WITH_NULL_SHA)],
    '0x0300C00C' => [qw(ECDH-RSA-RC4-SHA                ECDH_RSA_WITH_RC4_128_SHA)],
    '0x0300C018' => [qw(AECDH-AES128-SHA                ECDH_anon_WITH_AES_128_CBC_SHA)],
    '0x0300C019' => [qw(AECDH-AES256-SHA                ECDH_anon_WITH_AES_256_CBC_SHA)],
    '0x0300C017' => [qw(AECDH-DES-CBC3-SHA              ECDH_anon_WITH_DES_192_CBC3_SHA)],
    '0x0300C015' => [qw(AECDH-NULL-SHA                  ECDH_anon_WITH_NULL_SHA)],
    '0x0300C016' => [qw(AECDH-RC4-SHA                   ECDH_anon_WITH_RC4_128_SHA)],
    '0x03000013' => [qw(EDH-DSS-DES-CBC3-SHA            EDH_DSS_DES_192_CBC3_SHA)],
    '0x03000011' => [qw(EXP-EDH-DSS-DES-CBC-SHA         EDH_DSS_DES_40_CBC_SHA)],
    '0x03000012' => [qw(EDH-DSS-DES-CBC-SHA             EDH_DSS_DES_64_CBC_SHA)],
    '0x03000016' => [qw(EDH-RSA-DES-CBC3-SHA            EDH_RSA_DES_192_CBC3_SHA)],
    '0x03000014' => [qw(EXP-EDH-RSA-DES-CBC-SHA         EDH_RSA_DES_40_CBC_SHA)],
    '0x03000015' => [qw(EDH-RSA-DES-CBC-SHA             EDH_RSA_DES_64_CBC_SHA)],
    '0x0300001D' => [qw(FZA-FZA-SHA                     FZA_DMS_FZA_SHA)],     # FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA
    '0x0300001C' => [qw(FZA-NULL-SHA                    FZA_DMS_NULL_SHA)],    # FORTEZZA_KEA_WITH_NULL_SHA
    '0x0300001e' => [qw(FZA-RC4-SHA                     FZA_DMS_RC4_SHA)],     # <== 1e so that it is its own hash entry in crontrast to 1E (duplicate constant definition in openssl)
    '0x02050080' => [qw(IDEA-CBC-MD5                    IDEA_128_CBC_WITH_MD5)],
    '0x03000023' => [qw(KRB5-DES-CBC3-MD5               KRB5_DES_192_CBC3_MD5)],
    '0x0300001F' => [qw(KRB5-DES-CBC3-SHA               KRB5_DES_192_CBC3_SHA)],
    '0x03000029' => [qw(EXP-KRB5-DES-CBC-MD5            KRB5_DES_40_CBC_MD5)],
    '0x03000026' => [qw(EXP-KRB5-DES-CBC-SHA            KRB5_DES_40_CBC_SHA)],
    '0x03000022' => [qw(KRB5-DES-CBC-MD5                KRB5_DES_64_CBC_MD5)],
    '0x0300001E' => [qw(KRB5-DES-CBC-SHA                KRB5_DES_64_CBC_SHA)],
    '0x03000025' => [qw(KRB5-IDEA-CBC-MD5               KRB5_IDEA_128_CBC_MD5)],
    '0x03000021' => [qw(KRB5-IDEA-CBC-SHA               KRB5_IDEA_128_CBC_SHA)],
    '0x0300002A' => [qw(EXP-KRB5-RC2-CBC-MD5            KRB5_RC2_40_CBC_MD5)],
    '0x03000027' => [qw(EXP-KRB5-RC2-CBC-SHA            KRB5_RC2_40_CBC_SHA)],
    '0x03000024' => [qw(KRB5-RC4-MD5                    KRB5_RC4_128_MD5)],
    '0x03000020' => [qw(KRB5-RC4-SHA                    KRB5_RC4_128_SHA)],
    '0x0300002B' => [qw(EXP-KRB5-RC4-MD5                KRB5_RC4_40_MD5)],
    '0x03000028' => [qw(EXP-KRB5-RC4-SHA                KRB5_RC4_40_SHA)],
    '0x02ff0810' => [qw(NULL                            NULL)],
    '0x02000000' => [qw(NULL-MD5                        NULL_WITH_MD5)],
    '0x03000000' => [qw(NULL-MD5                        NULL_WITH_NULL_NULL)],
    '0x0300008A' => [qw(PSK-RC4-SHA                     PSK_WITH_RC4_128_SHA)],
    '0x0300008B' => [qw(PSK-3DES-EDE-CBC-SHA            PSK_WITH_3DES_EDE_CBC_SHA)],
    '0x0300008C' => [qw(PSK-AES128-CBC-SHA              PSK_WITH_AES_128_CBC_SHA)],
    '0x0300008D' => [qw(PSK-AES256-CBC-SHA              PSK_WITH_AES_256_CBC_SHA)],
    '0x02010080' => [qw(RC4-MD5                         RC4_128_WITH_MD5)],
    '0x02020080' => [qw(EXP-RC4-MD5                     RC4_128_EXPORT40_WITH_MD5)],
    '0x02030080' => [qw(RC2-CBC-MD5                     RC2_128_CBC_WITH_MD5)],
    '0x02040080' => [qw(EXP-RC2-CBC-MD5                 RC2_128_CBC_EXPORT40_WITH_MD5)],
    '0x02080080' => [qw(RC4-64-MD5                      RC4_64_WITH_MD5)],
    '0x0300000A' => [qw(DES-CBC3-SHA                    RSA_DES_192_CBC3_SHA)],
    '0x03000008' => [qw(EXP-DES-CBC-SHA                 RSA_DES_40_CBC_SHA)],
    '0x03000009' => [qw(DES-CBC-SHA                     RSA_DES_64_CBC_SHA)],
    '0x03000062' => [qw(EXP1024-DES-CBC-SHA             RSA_EXPORT1024_WITH_DES_CBC_SHA)],
    '0x03000061' => [qw(EXP1024-RC2-CBC-MD5             RSA_EXPORT1024_WITH_RC2_CBC_56_MD5)],
    '0x03000060' => [qw(EXP1024-RC4-MD5                 RSA_EXPORT1024_WITH_RC4_56_MD5)],
    '0x03000064' => [qw(EXP1024-RC4-SHA                 RSA_EXPORT1024_WITH_RC4_56_SHA)],
    '0x03000007' => [qw(IDEA-CBC-SHA                    RSA_IDEA_128_SHA)],
    '0x03000001' => [qw(NULL-MD5                        RSA_NULL_MD5)],
    '0x03000002' => [qw(NULL-SHA                        RSA_NULL_SHA)],
    '0x03000006' => [qw(EXP-RC2-CBC-MD5                 RSA_RC2_40_MD5)],
    '0x03000004' => [qw(RC4-MD5                         RSA_RC4_128_MD5)],
    '0x03000005' => [qw(RC4-SHA                         RSA_RC4_128_SHA)],
    '0x03000003' => [qw(EXP-RC4-MD5                     RSA_RC4_40_MD5)],
    '0x0300009C' => [qw(AES128-GCM-SHA256               RSA_WITH_AES_128_GCM_SHA256)],
    '0x0300002F' => [qw(AES128-SHA                      RSA_WITH_AES_128_SHA)],
    '0x0300003C' => [qw(AES128-SHA256                   RSA_WITH_AES_128_SHA256)],
    '0x0300009D' => [qw(AES256-GCM-SHA384               RSA_WITH_AES_256_GCM_SHA384)],
    '0x03000035' => [qw(AES256-SHA                      RSA_WITH_AES_256_SHA)],
    '0x0300003D' => [qw(AES256-SHA256                   RSA_WITH_AES_256_SHA256)],
    '0x03000041' => [qw(CAMELLIA128-SHA                 RSA_WITH_CAMELLIA_128_CBC_SHA)],
    '0x03000084' => [qw(CAMELLIA256-SHA                 RSA_WITH_CAMELLIA_256_CBC_SHA)],
    '0x030000BA' => [qw(CAMELLIA128-SHA256              RSA_WITH_CAMELLIA_128_CBC_SHA256)],
    '0x030000C0' => [qw(CAMELLIA256-SHA256              RSA_WITH_CAMELLIA_256_CBC_SHA256)],
    '0x0300003B' => [qw(NULL-SHA256                     RSA_WITH_NULL_SHA256)],
    '0x03000096' => [qw(SEED-SHA                        RSA_WITH_SEED_SHA)],

    '0x0300002C' => [qw(PSK-SHA                         PSK_WITH_NULL_SHA)],
    '0x0300002D' => [qw(DHE-PSK-SHA                     DHE_PSK_WITH_NULL_SHA)],
    '0x0300002E' => [qw(RSA-PSK-SHA                     RSA_PSK_WITH_NULL_SHA)],
    '0x0300008E' => [qw(DHE-PSK-RC4-SHA                 DHE_PSK_WITH_RC4_128_SHA)],
    '0x0300008F' => [qw(DHE-PSK-3DES-SHA                DHE_PSK_WITH_3DES_EDE_CBC_SHA)],
    '0x03000090' => [qw(DHE-PSK-AES128-SHA              DHE_PSK_WITH_AES_128_CBC_SHA)],
    '0x03000091' => [qw(DHE-PSK-AES256-SHA              DHE_PSK_WITH_AES_256_CBC_SHA)],
    '0x03000092' => [qw(RSA-PSK-RC4-SHA                 RSA_PSK_WITH_RC4_128_SHA)],
#   '0x03000093' => [qw(RSA-PSK-3DES-SHA                RSA_PSK_WITH_3DES_EDE_CBC_SHA)],
    '0x03000093' => [qw(RSA-PSK-3DES-EDE-CBC-SHA        RSA_PSK_WITH_3DES_EDE_CBC_SHA)],
    '0x03000094' => [qw(RSA-PSK-AES128-SHA              RSA_PSK_WITH_AES_128_CBC_SHA)],
#   '0x03000094' => [qw(RSA-PSK-AES128-CBC-SHA          RSA_PSK_WITH_AES_128_CBC_SHA)],     # openssl 1.0.2
    '0x03000095' => [qw(RSA-PSK-AES256-SHA              RSA_PSK_WITH_AES_256_CBC_SHA)],
#   '0x03000095' => [qw(RSA-PSK-AES128-CBC-SHA          RSA_PSK_WITH_AES_256_CBC_SHA)],     # openssl 1.0.2
    '0x030000AA' => [qw(DHE-PSK-AES128-GCM-SHA256       DHE_PSK_WITH_AES_128_GCM_SHA256)],
    '0x030000AB' => [qw(DHE-PSK-AES256-GCM-SHA384       DHE_PSK_WITH_AES_256_GCM_SHA384)],
    '0x030000AC' => [qw(RSA-PSK-AES128-GCM-SHA256       RSA_PSK_WITH_AES_128_GCM_SHA256)],
    '0x030000AD' => [qw(RSA-PSK-AES256-GCM-SHA384       RSA_PSK_WITH_AES_256_GCM_SHA384)],
    '0x030000AE' => [qw(PSK-AES128-SHA256               PSK_WITH_AES_128_CBC_SHA256)],
    '0x030000AF' => [qw(PSK-AES256-SHA384               PSK_WITH_AES_256_CBC_SHA384)],
    '0x030000B0' => [qw(PSK-SHA256                      PSK_WITH_NULL_SHA256)],
    '0x030000B1' => [qw(PSK-SHA384                      PSK_WITH_NULL_SHA384)],
    '0x030000B2' => [qw(DHE-PSK-AES128-SHA256           DHE_PSK_WITH_AES_256_CBC_SHA256)],
    '0x030000B3' => [qw(DHE-PSK-AES256-SHA384           DHE_PSK_WITH_AES_256_CBC_SHA384)],
    '0x030000B4' => [qw(DHE-PSK-SHA256                  DHE_PSK_WITH_NULL_SHA256)],
    '0x030000B5' => [qw(DHE-PSK-SHA384                  DHE_PSK_WITH_NULL_SHA384)],
    '0x030000B6' => [qw(RSA-PSK-AES128-SHA256           RSA_PSK_WITH_AES_256_CBC_SHA256)],
    '0x030000B7' => [qw(RSA-PSK-AES256-SHA384           RSA_PSK_WITH_AES_256_CBC_SHA384)],
    '0x030000B8' => [qw(RSA-PSK-SHA256                  RSA_PSK_WITH_NULL_SHA256)],
    '0x030000B9' => [qw(RSA-PSK-SHA384                  RSA_PSK_WITH_NULL_SHA384)],

    '0x0300C09C' => [qw(RSA-AES128-CCM                  RSA_WITH_AES_128_CCM)],
    '0x0300C09D' => [qw(RSA-AES256-CCM                  RSA_WITH_AES_256_CCM)],
    '0x0300C09E' => [qw(DHE-RSA-AES128-CCM              DHE_RSA_WITH_AES_128_CCM)],
    '0x0300C09F' => [qw(DHE-RSA-AES256-CCM              DHE_RSA_WITH_AES_256_CCM)],
    '0x0300C0A4' => [qw(PSK-RSA-AES128-CCM              PSK_WITH_AES_128_CCM)],
    '0x0300C0A5' => [qw(PSK-RSA-AES256-CCM              PSK_WITH_AES_256_CCM)],
    '0x0300C0AC' => [qw(ECDHE-RSA-AES128-CCM            ECDHE_ECDSA_WITH_AES_128_CCM)],
    '0x0300C0AD' => [qw(ECDHE-RSA-AES256-CCM            ECDHE_ECDSA_WITH_AES_256_CCM)],
    '0x0300C0A0' => [qw(RSA-AES128-CCM-8                RSA_WITH_AES_128_CCM_8)],
    '0x0300C0A1' => [qw(RSA-AES256-CCM-8                RSA_WITH_AES_256_CCM_8)],
    '0x0300C0A2' => [qw(DHE-RSA-AES128-CCM-8            DHE_RSA_WITH_AES_128_CCM_8)],
    '0x0300C0A3' => [qw(DHE-RSA-AES256-CCM-8            DHE_RSA_WITH_AES_256_CCM_8)],
    '0x0300C0A8' => [qw(PSK-RSA-AES128-CCM-8            PSK_WITH_AES_128_CCM_8)],
    '0x0300C0A9' => [qw(PSK-RSA-AES256-CCM-8            PSK_WITH_AES_256_CCM_8)],
    '0x0300C0AE' => [qw(ECDHE-RSA-AES128-CCM-8          ECDHE_ECDSA_WITH_AES_128_CCM_8)],
    '0x0300C0AF' => [qw(ECDHE-RSA-AES256-CCM-8          ECDHE_ECDSA_WITH_AES_256_CCM_8)],
    '0x03005600' => [qw(SCSV                            TLS_FALLBACK_SCSV)], # FIXME: according http://tools.ietf.org/html/7507.html
    '0x030000FF' => [qw(INFO_SCSV                       EMPTY_RENEGOTIATION_INFO_SCSV)],
    '0x0300C01C' => [qw(SRP-DSS-3DES-EDE-CBC-SHA        SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA)],
    '0x0300C01F' => [qw(SRP-DSS-AES-128-CBC-SHA         SRP_SHA_DSS_WITH_AES_128_CBC_SHA)],
    '0x0300C022' => [qw(SRP-DSS-AES-256-CBC-SHA         SRP_SHA_DSS_WITH_AES_256_CBC_SHA)],
    '0x0300C01B' => [qw(SRP-RSA-3DES-EDE-CBC-SHA        SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA)],
    '0x0300C01E' => [qw(SRP-RSA-AES-128-CBC-SHA         SRP_SHA_RSA_WITH_AES_128_CBC_SHA)],
    '0x0300C021' => [qw(SRP-RSA-AES-256-CBC-SHA         SRP_SHA_RSA_WITH_AES_256_CBC_SHA)],
    '0x0300C01A' => [qw(SRP-3DES-EDE-CBC-SHA            SRP_SHA_WITH_3DES_EDE_CBC_SHA)],
    '0x0300C01D' => [qw(SRP-AES-128-CBC-SHA             SRP_SHA_WITH_AES_128_CBC_SHA)],
    '0x0300C020' => [qw(SRP-AES-256-CBC-SHA             SRP_SHA_WITH_AES_256_CBC_SHA)],
    '0x0300FEE0' => [qw(RSA-FIPS-3DES-EDE-SHA           RSA_FIPS_WITH_3DES_EDE_CBC_SHA)],
    '0x0300FEE1' => [qw(RSA-FIPS-DES-CBC-SHA            RSA_FIPS_WITH_DES_CBC_SHA)],
    '0x0300FEFE' => [qw(RSA-FIPS-DES-CBC-SHA            RSA_FIPS_WITH_DES_CBC_SHA)],
    '0x0300FEFF' => [qw(RSA-FIPS-3DES-EDE-SHA           RSA_FIPS_WITH_3DES_EDE_CBC_SHA)],
    '0x03000080' => [qw(GOST94-GOST89-GOST89            GOSTR341094_WITH_28147_CNT_IMIT)],
    '0x03000081' => [qw(GOST2001-GOST89-GOST89          GOSTR341001_WITH_28147_CNT_IMIT)],
    '0x0300FF00' => [qw(GOST-MD5             -?-)],  # ??
    '0x0300FF01' => [qw(GOST-GOST94          -?-)],  # ??
    '0x0300FF00' => [qw(GOST94-NULL-GOST94   -?-)],  # ??
    '0x0300FF01' => [qw(GOST2001-NULL-GOST94 -?-)],  # ??
# TODO:  following PCT...
    '0x00800001' => [qw(PCT_SSL_CERT_TYPE               PCT1_CERT_X509)],
    '0x00800003' => [qw(PCT_SSL_CERT_TYPE               PCT1_CERT_X509_CHAIN)],
    '0x00810001' => [qw(PCT_SSL_HASH_TYPE               PCT1_HASH_MD5)],
    '0x00810003' => [qw(PCT_SSL_HASH_TYPE               PCT1_HASH_SHA)],
    '0x00820003' => [qw(PCT_SSL_EXCH_TYPE               PCT1_EXCH_RSA_PKCS1)],
    '0x00823004' => [qw(PCT_SSL_CIPHER_TYPE_1ST_HALF    PCT1_CIPHER_RC4)],
    '0x00842840' => [qw(PCT_SSL_CIPHER_TYPE_2ND_HALF    PCT1_ENC_BITS_40|PCT1_MAC_BITS_128)],
    '0x00848040' => [qw(PCT_SSL_CIPHER_TYPE_2ND_HALF    PCT1_ENC_BITS_128|PCT1_MAC_BITS_128)],
    '0x008f8001' => [qw(PCT_SSL_COMPAT                  PCT_VERSION_1)],
    #!#----------+-------------------------------------+--------------------------+

    # Note(c)
    #   according https://tools.ietf.org/html/draft-ietf-tls-chacha20-poly1305-04
    #   some hex keys for ciphers changed

); # %cipher_names

our %cipher_alias = ( # TODO: list not yet used
    #!#----------+-------------------------------------+--------------------------+
    #!# constant =>     cipher suite name alias        # comment (where found)
    #!#----------+-------------------------------------+--------------------------+
    '0x02030080' => [qw(RC2-MD5)],                     # 
    '0x02040080' => [qw(EXP-RC2-MD5)],                 # from sslaudit.ini
    '0x03000012' => [qw(EDH-DSS-CBC-SHA)],             # from sslaudit.ini and mozilla
    '0x0300001D' => [qw(FZA-FZA-CBC-SHA)],
    '0x03000032' => [qw(EDH-DSS-AES128-SHA)],          # from RSA BSAFE SSL-C
    '0x03000033' => [qw(EDH-RSA-AES128-SHA)],          # from RSA BSAFE SSL-C
    '0x03000038' => [qw(EDH-DSS-AES256-SHA)],          # from RSA BSAFE SSL-C
    '0x03000039' => [qw(EDH-RSA-AES256-SHA)],          # from RSA BSAFE SSL-C
    '0x03000062' => [qw(EXP-DES-56-SHA)],              # from RSA BSAFE SSL-C
    '0x03000063' => [qw(EXP-EDH-DSS-DES-56-SHA)],      # from RSA BSAFE SSL-C
    '0x03000064' => [qw(EXP-RC4-56-SHA)],              # from RSA BSAFE SSL-C
    '0x03000065' => [qw(EXP-EDH-DSS-RC4-56-SHA)],
    '0x03000066' => [qw(EDH-DSS-RC4-SHA)],             # from RSA BSAFE SSL-C
    '0x0300009B' => [qw(DHanon-SEED-SHA)],
    #!#----------+-------------------------------------+--------------------------+
); # %cipher_alias

our %text = (
    'separator'     => ":",# separator character between label and value
    # texts may be redefined
    'undef'         => "<<undefined>>",
    'response'      => "<<response>>",
    'protocol'      => "<<protocol probably supported, but no ciphers accepted>>",
    'need-cipher'   => "<<check possible in conjunction with +cipher only>>",
    'no-STS'        => "<<N/A as STS not set>>",
    'no-dns'        => "<<N/A as --no-dns in use>>",
    'no-cert'       => "<<N/A as --no-cert in use>>",
    'no-http'       => "<<N/A as --no-http in use>>",
    'no-tlsextdebug'=> "<<N/A as --no-tlsextdebug in use>>",
    'no-nextprotoneg'=>"<<N/A as --no-nextprotoneg in use>>",
    'no-resonnect'  => "<<N/A as --no-resonnect in use>>",
    'disabled'      => "<<N/A as @@ in use>>",     # @@ is --no-SSLv2 or --no-SSLv3
    'protocol'      => "<<N/A as protocol disabled or NOT YET implemented>>",     # @@ is --no-SSLv2 or --no-SSLv3
    'miss-RSA'      => " <<missing ECDHE-RSA-* cipher>>",
    'miss-ECDSA'    => " <<missing ECDHE-ECDSA-* cipher>>",
    'missing'       => " <<missing @@>>",
    'EV-large'      => " <<too large @@>>",
    'EV-subject-CN' => " <<missmatch: subject CN= and commonName>>",
    'EV-subject-host'=>" <<missmatch: subject CN= and given hostname>>",
    'no-reneg'      => " <<secure renegotiation not supported>>",
    'cert-dates'    => " <<invalid certificate date>>",
    'cert-valid'    => " <<certificate validity to large @@>>",
    'cert-chars'    => " <<invalid charcters in @@>>",
    'wildcards'     => " <<uses wildcards:@@>>",
    'gethost'       => " <<gethostbyaddr() failed>>",
    'out-target'    => "\n==== Target: @@ ====\n",
    'out-ciphers'   => "\n=== Ciphers: Checking @@ ===",
    'out-infos'     => "\n=== Informations ===",
    'out-scoring'   => "\n=== Scoring Results EXPERIMENTAL ===",
    'out-checks'    => "\n=== Performed Checks ===",
    'out-list'      => "=== List @@ Ciphers ===",
    'out-summary'   => "=== Ciphers: Summary @@ ==",
    # hostname texts
    'host-host'     => "Given hostname",
    'host-IP'       => "IP for given hostname",
    'host-rhost'    => "Reverse resolved hostname",
    'host-DNS'      => "DNS entries for given hostname",
    # misc texts
    'cipher'        => "Cipher",
    'support'       => "supported",
    'security'      => "Security",
    'dh-param'      => "DH Parameters",
    'desc'          => "Description",
    'desc-check'    => "Check Result (yes is considered good)",
    'desc-info'     => "Value",
    'desc-score'    => "Score (max value 100)",

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
        #     printtitle, print_cipherhead, printfooter, print_cipherdefault, print_ciphertotals
    },
    # NOTE: all other legacy texts are hardcoded, as there is no need to change them!

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

# save hardcoded settings (command lists, texts); used in o-saft-dbx.pm
our %org = (
    'cmd-check' => $cfg{'cmd-check'},
    'cmd-http'  => $cfg{'cmd-http'},
    'cmd-info'  => $cfg{'cmd-info'},
    'cmd-quick' => $cfg{'cmd-quick'},
); # %org

## incorporate some environment variables
## -------------------------------------
$cmd{'openssl'}     = $ENV{'OPENSSL'}      if (defined $ENV{'OPENSSL'});
$cfg{'openssl_cnf'} = $ENV{'OPENSSL_CONF'} if (defined $ENV{'OPENSSL_CONF'});
$cfg{'openssl_fips'}= $ENV{'OPENSSL_FIPS'} if (defined $ENV{'OPENSSL_FIPS'});
if (defined $ENV{'LIBPATH'}) {
    print STR_HINT, "LIBPATH environment variable found, consider using '--envlibvar=LIBPATH'\n";
    # TODO: avoid hint if --envlibvar=LIBPATH in use
    # $cmd{'envlibvar'} = $ENV{'LIBPATH'}; # don't set silently
}

#_init_all();  # call delayed to prevent warning of prototype check with -w

_y_EXIT("exit=INIT1 - initialization end");
usr_pre_file();

## definitions: internal functions
## -------------------------------------
sub _initchecks_score() {
    # set all default score values here
    $checks{$_}->{score} = 10 foreach (keys %checks);
    # some special values %checks{'sts_maxage*'}
    $checks{'sts_maxage0d'}->{score} =   0; # very weak
    $checks{'sts_maxage1d'}->{score} =  10; # weak
    $checks{'sts_maxage1m'}->{score} =  20; # low
    $checks{'sts_maxage1y'}->{score} =  70; # medium
    $checks{'sts_maxagexy'}->{score} = 100; # high
    foreach (keys %checks) {
        $checks{$_}->{score} = 90 if (m/WEAK/i);
        $checks{$_}->{score} = 30 if (m/LOW/i);
        $checks{$_}->{score} = 10 if (m/MEDIUM/i);
    }
} # _initchecks_score

sub _initchecks_prot() {
    #? initialize default values in %prot
    my $ssl;
    foreach $ssl (keys %prot) {
        $prot{$ssl}->{'cnt'}        = 0;
        $prot{$ssl}->{'-?-'}        = 0;
        $prot{$ssl}->{'WEAK'}       = 0;
        $prot{$ssl}->{'LOW'}        = 0;
        $prot{$ssl}->{'MEDIUM'}     = 0;
        $prot{$ssl}->{'HIGH'}       = 0;
        $prot{$ssl}->{'protocol'}   = 0;
        $prot{$ssl}->{'default'}    = STR_UNDEF;
        $prot{$ssl}->{'pfs_cipher'} = STR_UNDEF;
        $prot{$ssl}->{'pfs_ciphers'}= [];
    }
} # _initchecks_prot

sub _initchecks_val()  {
    # set all default check values here
    $checks{$_}->{val}   = "" foreach (keys %checks);
    # some special values %checks{'sts_maxage*'}
    $checks{'sts_maxage0d'}->{val}  =        0;
    $checks{'sts_maxage1d'}->{val}  =    86400; # day
    $checks{'sts_maxage1m'}->{val}  =  2592000; # month
    $checks{'sts_maxage1y'}->{val}  = 31536000; # year
    $checks{'sts_maxagexy'}->{val}  = 99999999;
    foreach (keys %checks) {
        $checks{$_}->{val}   =  0 if (m/$cfg{'regex'}->{'cmd-sizes'}/);
        $checks{$_}->{val}   =  0 if (m/$cfg{'regex'}->{'SSLprot'}/);
    }
    # initialize counter for cipher
    _initchecks_prot();
} # _initchecks_val

sub _init_all()        {
    # set all default values here
    $cfg{'done'}->{'init_all'}++;
    _trace("_init_all(){}");
    _initchecks_score();
    _initchecks_val();
} # _init_all
_init_all();   # initialize defaults in %checks (score, val)

sub _resetchecks()     {
    # reset values
    foreach (keys %{$cfg{'done'}}) {
        next if (!m/^check/);  # only reset check*
        $cfg{'done'}->{$_} = 0;
    }
    $cfg{'done'}->{'ciphers_all'} = 0;
    $cfg{'done'}->{'ciphers_get'} = 0;
    _initchecks_val();
}

sub _prot_cipher($$)   { return " " . join(":", @_); }
    # return string consisting of given parameters separated by : and prefixed with a space
    # (mainly used to concatenate SSL Version and cipher suite name)

sub _getscore($$$)     {
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

sub _cfg_set($$)       {
    # set value in configuration %checks, %text
    # $typ must be any of: CFG-text, CFG-score, CFG-cmd-*
    # if given value is a file, read settings from that file
    # otherwise given value must be KEY=VALUE format;
    my $typ = shift;    # type of config value to be set
    my $arg = shift;    # KEY=VAL or filename
    my ($key, $val);
    no warnings qw(prototype); # avoid: main::_cfg_set() called too early to check prototype at ...
    _trace("_cfg_set($typ, ){");
    if ($typ !~ m/^CFG-(cmd|checks?|data|text|scores?)$/) {
        _warn("unknown configuration key '$typ'; setting ignored");
        goto _CFG_RETURN;
    }
    if (($arg =~ m|^[a-zA-Z0-9,._+#()\/-]+|) and (-f "$arg")) { # read from file
        # we're picky about valid filenames: only characters, digits and some
        # special chars (this should work on all platforms)
        if ($cgi == 0) {
            _warn("configuration files are not read in CGI mode; ignored");
            return;
        }
        _trace("_cfg_set: read $arg \n");
        my $line ="";
        open(FID, $arg) && do {
            push(@dbxfile, $arg);
            _print_read("$arg", "USER-FILE configuration file") if ($cfg{'out_header'} > 0);
            while ($line = <FID>) {
                #
                # format of each line in file must be:
                #    Lines starting with  =  are comments and ignored.
                #    Anthing following (and including) a hash is a comment
                #    and ignored. Empty lines are ignored.
                #    Settings must be in format:  key=value
                #       where white spaces are allowed arround =
                chomp $line;
                $line =~ s/\s*#.*$// if ($typ !~ m/^CFG-text/i);
                    # remove trailing comments, but CFG-text may contain hash (#)
                next if ($line =~ m/^\s*=/);# ignore our header lines (since 13.12.11)
                next if ($line =~ m/^\s*$/);# ignore empty lines
                _trace("_cfg_set: set $line ");
                _cfg_set($typ, $line);
            }
            close(FID);
            goto _CFG_RETURN;
        };
        _warn("cannot open '$arg': $! ; file ignored");
        return;
    } # read file

    ($key, $val) = split(/=/, $arg, 2); # left of first = is key
    $key =~ s/[^a-zA-Z0-9_?=+-]*//g;    # strict sanatize key
    $val =  "" if (!defined $val);      # avoid warnings when not KEY=VALUE

    if ($typ eq 'CFG-cmd') {            # set new list of commands $arg
        $typ = 'cmd-' . $key ;# the command to be set, i.e. cmd-http, cmd-sni, ...
        _trace("_cfg_set: KEY=$key, CMD=$val");
        @{$cfg{$typ}} = ();
        push(@{$cfg{$typ}}, split(/\s+/, $val));
        foreach $key (@{$cfg{$typ}}) {  # check for mis-spelled commands
            next if (_is_hashkey($key, \%checks) > 0);
            next if (_is_hashkey($key, \%data) > 0);
            next if (_is_intern( $key) > 0);
            next if (_is_member( $key, \@{$cfg{'cmd-NL'}}) > 0);
            if ($key eq 'default') {    # valid before 14.11.14; behave smart for old rc-files
                push(@{$cfg{$typ}}, 'selected');
                _warn("please use '+selected' instead of '+$key'; setting ignored");
                next;
            }
            _warn("unknown command '+$key' for '$typ'; setting ignored");
        }
    }

    # invalid keys are silently ignored (perl is that clever:)

    if ($typ eq 'CFG-score') {          # set new score value
        _trace("_cfg_set: KEY=$key, SCORE=$val");
        if ($val !~ m/^(\d\d?|100)$/) { # allow 0 .. 100
            _warn("invalid score value '$val'; setting ignored");
            goto _CFG_RETURN;
        }
        $checks{$key}->{score} = $val if ($checks{$key});
    }

    if ($typ =~ /^CFG-(checks?|data|scores|text)/) {
        $val =~ s/(\\n)/\n/g;
        $val =~ s/(\\r)/\r/g;
        $val =~ s/(\\t)/\t/g;
        _trace("_cfg_set: KEY=$key, LABEL=$val");
        $checks{$key}->{txt} = $val if ($typ =~ /^CFG-check/);
        $data{$key}  ->{txt} = $val if ($typ =~ /^CFG-data/);
        $text{$key}          = $val if ($typ =~ /^CFG-text/);
        $scores{$key}->{txt} = $val if ($typ =~ /^CFG-scores/);
        $scores{$key}->{txt} = $val if ($key =~ m/^check_/); # contribution to lazy usage
    }

    _CFG_RETURN:
    _trace("_cfg_set() }");
    return;
} # _cfg_set

# check functions for array members and hash keys
sub __SSLinfo($$$)     {
    # wrapper for Net::SSLinfo::*() functions
    # Net::SSLinfo::*() return raw data, depending on $cfg{'format'}
    # these values will be converted to o-saft's preferred format
    my $cmd = shift;
    my $val = "<<__SSLinfo: unknown command: '$cmd'>>";
    my $ext = "";
    $val =  Net::SSLinfo::fingerprint(      $_[0], $_[1]) if ($cmd eq 'fingerprint');
    $val =  Net::SSLinfo::fingerprint_hash( $_[0], $_[1]) if ($cmd eq 'fingerprint_hash');
    $val =  Net::SSLinfo::fingerprint_sha1( $_[0], $_[1]) if ($cmd eq 'fingerprint_sha1');
    $val =  Net::SSLinfo::fingerprint_md5(  $_[0], $_[1]) if ($cmd eq 'fingerprint_md5');
    $val =  Net::SSLinfo::pubkey_value(     $_[0], $_[1]) if ($cmd eq 'pubkey_value');
    $val =  Net::SSLinfo::sigkey_value(     $_[0], $_[1]) if ($cmd eq 'sigkey_value');
    $val =  Net::SSLinfo::heartbeat(        $_[0], $_[1]) if ($cmd eq 'heartbeat');
    $val =  Net::SSLinfo::tlsextdebug(      $_[0], $_[1]) if ($cmd eq 'tlsextdebug');
    $val =  Net::SSLinfo::tlsextensions(    $_[0], $_[1]) if ($cmd eq 'tlsextensions');
    $val =  Net::SSLinfo::extensions(       $_[0], $_[1]) if ($cmd =~ /^ext(?:ensions|_)/);
    if ($cmd =~ m/ext_/) {
        # all following are part of Net::SSLinfo::extensions(), now extract parts
        # The extension section in the certificate starts with
        #    X509v3 extensions:
        # then each extension starts with a string prefixed by  X509v3
        # except following:
        #    Authority Information Access
        #    Netscape Cert Type
        # these are handled in regex below which matches next extension, if any.
        $val .= " X509";# add string to match last extenion also
        my $rex = '\s*(.*?)(?:X509|Authority|Netscape).*';
        $ext = $val;
        $val =~ s#.*?Authority Information Access:$rex#$1#ms    if ($cmd eq 'ext_authority');
        $val =~ s#.*?Authority Key Identifier:$rex#$1#ms        if ($cmd eq 'ext_authorityid');
        $val =~ s#.*?Basic Constraints:$rex#$1#ms               if ($cmd eq 'ext_constraints');
        $val =~ s#.*?Key Usage:$rex#$1#ms                       if ($cmd eq 'ext_keyusage');
        $val =~ s#.*?Subject Key Identifier:$rex#$1#ms          if ($cmd eq 'ext_subjectkeyid');
        $val =~ s#.*?Certificate Policies:$rex#$1#ms            if ($cmd =~ /ext_cps/);
        $val =~ s#.*?CPS\s*:\s*([^\s\n]*).*#$1#ms               if ($cmd eq 'ext_cps_cps');
        $val =~ s#.*?Policy\s*:\s*(.*?)(?:CPS|User).*#$1#ims    if ($cmd eq 'ext_cps_policy');
        $val =~ s#.*?CRL Distribution Points:$rex#$1#ms         if ($cmd =~ /ext_crl/);
        $val =~ s#.*?Extended Key Usage:$rex#$1#ms              if ($cmd eq 'ext_extkeyusage');
        $val =~ s#.*?Netscape Cert Type:$rex#$1#ms              if ($cmd eq 'ext_certtype');
        $val =~ s#.*?Issuer Alternative Name:$rex#$1#ms         if ($cmd eq 'ext_issuer');
        #$val =~ s#.*?(URI\s*:.*)#$1#ms                          if ($cmd eq 'ext_crl_crl');
# TODO: previous fails, reason unknown
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
        $val =  "" if (!defined $val);  # avoid warnings
        $val =~ s/\n\s+//g; # remove trailing spaces
        $val =~ s/\n/ /g;
        $val =~ s/\s\s+//g; # remove multiple spaces
        $val =~ s/([0-9a-f]):([0-9a-f])/$1$2/ig; # remove : inside hex (quick&dirty)
    }
    return $val;
}; # __SSLinfo

sub _subst($$)         { my $is=shift; $is=~s/@@/$_[0]/;  return $is; }
    # return given text with '@@' replaced by given value
sub _need_this($)      {
    # returns >0 if any of the given commands is listed in $cfg{'$_'}
    my $key = shift;
    my $is  = join("|", @{$cfg{'do'}});
       $is  =~ s/\+/\\+/g;    # we have commands with +, needs to be escaped
    return grep(/^($is)$/,  @{$cfg{$key}});
}
sub _need_cipher()     { return _need_this('need_cipher');   };
sub _need_default()    { return _need_this('need_default');  };
sub _need_checkssl()   { return _need_this('need_checkssl'); };
    # returns >0 if any of the given commands is listed in $cfg{need_*}
sub _is_hashkey($$)    { my $is=shift; return grep({lc($is) eq lc($_)} keys %{$_[0]}); }
sub _is_member($$)     { my $is=shift; return grep({lc($is) eq lc($_)}      @{$_[0]}); }
sub _is_do($)          { my $is=shift; return _is_member($is, \@{$cfg{'do'}}); }
sub _is_intern($)      { my $is=shift; return _is_member($is, \@{$cfg{'cmd-intern'}}); }
sub _is_hexdata($)     { my $is=shift; return _is_member($is, \@{$cfg{'data_hex'}});   }
sub _is_call($)        { my $is=shift; return _is_member($is, \@{$cmd{'call'}}); }
    # returns >0 if any of the given string is listed in $cfg{*}

# some people prefer to use a getter function to get data from objects
# each function returns a spcific value (column) from the %cipher table
# see %ciphers_desc about description of the columns
sub get_cipher_sec($)  { my $c=$_[0]; return $ciphers{$c}[0] || "" if (grep(/^$c/, %ciphers)>0); return ""; }
sub get_cipher_ssl($)  { my $c=$_[0]; return $ciphers{$c}[1] || "" if (grep(/^$c/, %ciphers)>0); return ""; }
sub get_cipher_enc($)  { my $c=$_[0]; return $ciphers{$c}[2] || "" if (grep(/^$c/, %ciphers)>0); return ""; }
sub get_cipher_bits($) { my $c=$_[0]; return $ciphers{$c}[3] || "" if (grep(/^$c/, %ciphers)>0); return ""; }
sub get_cipher_mac($)  { my $c=$_[0]; return $ciphers{$c}[4] || "" if (grep(/^$c/, %ciphers)>0); return ""; }
sub get_cipher_auth($) { my $c=$_[0]; return $ciphers{$c}[5] || "" if (grep(/^$c/, %ciphers)>0); return ""; }
sub get_cipher_keyx($) { my $c=$_[0]; return $ciphers{$c}[6] || "" if (grep(/^$c/, %ciphers)>0); return ""; }
sub get_cipher_score($){ my $c=$_[0]; return $ciphers{$c}[7] || "" if (grep(/^$c/, %ciphers)>0); return ""; }
sub get_cipher_tags($) { my $c=$_[0]; return $ciphers{$c}[8] || "" if (grep(/^$c/, %ciphers)>0); return ""; }
sub get_cipher_desc($) { my $c=$_[0];
    # get description for specified cipher from %ciphers
    if (! defined $ciphers{$c}) {
        _warn("undefined cipher description for '$c'"); # TODO: correct %ciphers
        return STR_UNDEF;
    }
    my @c = @{$ciphers{$c}}; 
    shift @c;
    return @c if (grep(/^$c/, %ciphers)>0);
    return "";
}

sub get_cipher_hex($)  {
    # find hex key for cipher in %cipher_names or %cipher_alias
    my $c = shift;
    my $k = "";
    foreach $k (keys %cipher_names) { # database up to VERSION 14.07.14
        return $k if (($cipher_names{$k}[0] eq $c) or ($cipher_names{$k}[1] eq $c));
    }
    foreach $k (keys %cipher_alias) { # not yet found, check for alias
        return $k if ($cipher_alias{$k}[0] eq $c);
    }
    return "";
} # get_cipher_hex

sub get_cipher_name($) {
    # check if given cipher name is a known cipher
    # checks in %cipher_names if nof found in %ciphers
    my $cipher  = shift;
    return $cipher if (grep(/^$cipher/, %ciphers)>0);
    _trace("get_cipher_name: search $cipher");
    foreach (keys %cipher_names) {
        return $cipher_names{$_}[0] if ($cipher =~ m/$cipher_names{$_}[0]/);
        return $cipher_names{$_}[0] if ($cipher_names{$_}[1] =~ /$cipher/);
    }
    # nothing found yet, try more lazy match
    foreach (keys %cipher_names) {
        if ($cipher_names{$_}[0] =~ m/$cipher/) {
            _warn("partial match for cipher name found '$cipher'");
            return $cipher_names{$_}[0];
        }
    }
    return "";
} # get_cipher_name

## definitions: check functions
## -------------------------------------
sub _setvalue($){ return ($_[0] eq "") ? 'yes' : 'no (' . $_[0] . ')'; }
    # return 'yes' if given value is empty, return 'no' otherwise
sub _isbeast($$){
    # return given cipher if vulnerable to BEAST attack, empty string otherwise
    my ($ssl, $cipher) = @_;
    return ""      if ($ssl    !~ /(SSLv3|TLSv11?)/); # SSLv2 and TLSv1.2 not vulnerable to BEAST
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'BEAST'}/);
    return "";
} # _isbeast
### _isbreach($)       { return "NOT YET IMPLEMEMNTED"; }
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
sub _iscrime($) { return ($_[0] =~ /$cfg{'regex'}->{'nocompression'}/) ? ""  : $_[0] . " "; }
    # return compression if available, empty string otherwise
sub _islucky($) { return ($_[0] =~ /$cfg{'regex'}->{'Lucky13'}/) ? $_[0] : ""; }
    # return given cipher if vulnerable to Lucky 13 attack, empty string otherwise
sub _istime($)  { return 0; } # TODO: checks; good: AES-GCM or AES-CCM
sub _isfreak($$){
    # return given cipher if vulnerable to FREAK attack, empty string otherwise
    my ($ssl, $cipher) = @_;
    return ""      if ($ssl    !~ /(SSLv3)/); # TODO: probaly only SSLv3 is vulnerable
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'FREAK'}/);
    return "";
} # _isfreak
sub _islogjam($$) {
    # return given cipher if vulnerable to logjam attack, empty string otherwise
    my ($ssl, $cipher) = @_;
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'Logjam'}/);
} # _islogjam
sub _issloth($$) {
    # return given cipher if vulnerable to SLOTH attack, empty string otherwise
    my ($ssl, $cipher) = @_;
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'SLOTH'}/);
} # _issloth
sub _ispfs($$)  { return ("$_[0]-$_[1]" =~ /$cfg{'regex'}->{'PFS'}/)   ? ""  : $_[1]; }
    # return given cipher if it does not support forward secret connections (PFS)
sub _isrc4($)   { return ($_[0] =~ /$cfg{'regex'}->{'RC4'}/)  ? $_[0] . " "  : ""; }
    # return given cipher if it is RC4
sub _istr02102($$) {
    # return given cipher if it is not TR-02102 compliant, empty string otherwise
    my ($ssl, $cipher) = @_;
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'EXPORT'}/);
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'notTR-02102'}/);
    return $cipher if ($cipher !~ /$cfg{'regex'}->{'TR-02102'}/);
# FIXME: check for SHA1 missing, which is a lazy accept, see TR-02102-2 3.2.2
    return "";
} # _istr02102
sub _istr03116_strict($$) {
    # return given cipher if it is not TR-03116 compliant, empty string otherwise
    my ($ssl, $cipher) = @_;
    return $cipher if ($ssl    ne "TLSv12");
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'EXPORT'}/);
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'notTR-03116'}/);
    return $cipher if ($cipher !~ /$cfg{'regex'}->{'TR-03116+'}/);
    return "";
} # _istr03116_strict
sub _istr03116_lazy($$) {
    # return given cipher if it is not TR-03116 compliant, empty string otherwise
    my ($ssl, $cipher) = @_;
    return $cipher if ($ssl    ne "TLSv12");
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'EXPORT'}/);
    return $cipher if ($cipher !~ /$cfg{'regex'}->{'TR-03116-'}/);
    return "";
} # _istr03116_lazy
sub _isrfc7525($$) {
    # return given cipher if it is not RFC 7525 compliant, empty string otherwise
    my ($ssl, $cipher) = @_;
    return $cipher if ($ssl    ne "TLSv12");
   #return $cipher if ($cipher =~ /$cfg{'regex'}->{'notRFC7525'}/);
    return $cipher if ($cipher !~ /$cfg{'regex'}->{'RFC7525'}/);
    return "";
} # _isrfc7525
sub _isfips($$) {
    # return given cipher if it is not FIPS-140 compliant, empty string otherwise
    my ($ssl, $cipher) = @_;
    return $cipher if ($ssl    ne "TLSv1");
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'notFIPS-140'}/);
    return $cipher if ($cipher !~ /$cfg{'regex'}->{'FIPS-140'}/);
    return "";
} # _isfips
sub _isnsab($$) {
    # return given cipher if it is not NSA Suite B compliant, empty string otherwise
# TODO:
} # _isnsab
sub _ispci($$)  {
    # return given cipher if it is not PCI compliant, empty string otherwise
# TODO: DH 1024+ is PCI compliant
    my ($ssl, $cipher) = @_;
    return $cipher if ($ssl    eq "SSLv2"); # SSLv2 is not PCI compliant
    return $cipher if ($cipher =~ /$cfg{'regex'}->{'notPCI'}/);
    return "";
} # _ispci
sub _readframe($) {
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
            my ($ht,$len) = unpack("Ca3",substr($buf,0,4,''));
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
sub _isbleed($$) {
    #? return "heartbleed" if target supports TLS extension 15 (heartbeat), empty string otherwise
    # http://heartbleed.com/
    # http://possible.lv/tools/hb/
    # http://filippo.io/Heartbleed/
    # https://github.com/proactiveRISK/Heartbleed
    # https://www.cloudflarechallenge.com/heartbleed
    my ($host, $port) = @_;
    my $heartbeats    = 1;
    my $cl  = undef; # TODO: =$Net::SSLinfo::socket;
    my $ret = "";       # empty string as required in %checks
    my ($type,$ver,$buf,@msg) = ("", "", "", ());
    local $\;
    undef $\;           # take care, must not be \n !!

        # open our own connection and close it at end
# TODO: does not work with socket from SSLinfo.pm
# TODO: following unless{}else{} should be same as in _usesocket()
    unless (($cfg{'starttls'}) || (($cfg{'proxyhost'})&&($cfg{'proxyport'}))) {
        # no proxy and not starttls
        $cl = IO::Socket::INET->new(PeerAddr=>"$host:$port", Timeout=>$cfg{'timeout'}) or do {
            _warn("_isbleed: failed to connect: '$!'");
            return "failed to connect";
        };
    } else {
        # proxy or starttls
        _trace("_isbleed: using 'Net::SSLhello'");
        $cl = Net::SSLhello::openTcpSSLconnection($host, $port);
        if ((!defined ($cl)) || ($@)) { # No SSL Connection
            $@ = " Did not get a valid SSL-Socket from Function openTcpSSLconnection -> Fatal Exit of openTcpSSLconnection" unless ($@);
            _warn ("_isbleed (with openTcpSSLconnection): $@\n");
            _trace("_isbleed: Fatal Exit in _doCheckSSLciphers }\n");
            return("failed to connect");
        }
        # NO SSL upgrade needed -> NO else
    }

    # all following code stolen from Steffen Ullrich (08. April 2014):
    #   https://github.com/noxxi/p5-scripts/blob/master/check-ssl-heartbleed.pl
    # code slightly adapted to our own variables: $host, $port, $cfg{'timeout'}
    # also die() replaced by warn()

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
            _warn("no reply: '$!'");
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
    return $ret;
} # _isbleed

sub _isccs($$$) {
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
        _warn("failed to connect: '$!'");
        return "failed to connect";
    };
#################
# $ccs = _isccs($host, $port, $ssl);
#    'openssl_version_map' => {  # map our internal option to openssl version (hex value)
#        'SSLv2'=> 0x0002, 'SSLv3'=> 0x0300, 'TLSv1'=> 0x0301, 'TLSv11'=> 0x0302, 'TLSv12'=> 0x0303, 'TLSv13'=> 0x0304,
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
            _warn("no reply: '$!'");
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

sub _getwilds($$) {
    # compute usage of wildcard in CN and subjectAltname
    my ($host, $port) = @_;
    my ($value, $regex);
    $value = $data{'cn'}->{val}($host);
    $checks{'wildcard'}->{val} = "<<CN:>>$value" if ($value =~ m/[*]/);
    foreach $value (split(" ", $data{'altname'}->{val}($host))) {
            $value =~ s/.*://;      # strip prefix
        if ($value =~ m/\*/) {
            $checks{'wildcard'}->{val} .= " " . $value;
            ($regex = $value) =~ s/[*]/.*/;   # make regex (miss dots is ok)
            $checks{'wildhost'}->{val}  = $value if ($host =~ m/$regex/);
            $checks{'cnt_wildcard'}->{val}++;
        }
        $checks{'cnt_altname'}->{val}++;
        $checks{'len_altname'}->{val} = length($value) + 1; # count number of characters + type (int)
    }
    # checking for SNI does not work here 'cause it destroys %data
} # _getwilds

sub _get_dhparam($$) {
    #? parse output of `openssl -msg' and returns DH parameters; empty if none found
    my ($cipher, $data) = @_;
    if ($data =~ m#Server Temp Key:#) {
        $data =~ s/.*?Server Temp Key:\s*([^\n]*)\n.*/$1/si;
        _trace("_get_dhparam(){ Server Temp Key\t= $data }");
        return $data;
    }
    # else continue extracting DH parameters from ServerKeyExchange-Message
    my $dh = "";
    # we may get a ServerKeyExchange-Message with the -msg option
    # <<< TLS 1.2 Handshake [length 040f], ServerKeyExchange
    #     0c 00 04 0b 01 00 c1 41 38 da 2e b3 7e 68 71 31
    #     86 da 01 e5 95 fa 7e 83 9b a2 28 1b a5 fb d2 72
    #     ...
    # >>> TLS 1.2 ChangeCipherSpec [length 0001]
    return "" if ($data !~ m#ServerKeyExchange#);

    $data =~ s#.*?Handshake\s*?\[length\s*([0-9a-fA-F]{2,4})\]\,?\s*?ServerKeyExchange\s*[\n\r]+(.*?)[\n\r][<>]+.*#$1_$2#si;
    _trace("_get_dhparam: #{ DHE RAW data:\n$data\n#}\n");
    $data =~ s/\s+/ /gi;          # squeeze multible spaces
    $data =~ s/[^0-9a-f_]//gi;    # remove all none hex characters and non seperator
    my ($lenStr, $len) = 0;
    ($lenStr, $data) = split('_', $data);   # 2 strings with Hex Octetts!
    _trace3("_get_dhparam: #{ DHE RAW data): len: $lenStr\n$data\n#}\n");
    $len = hex($lenStr);
    my $message = pack("H*", $data);

    # parse message header
    my $msgData = "";
    my ($msgType, $msgFirstByte, $msgLen) = 0;
       ($msgType,       # C
        $msgFirstByte,  # C
        $msgLen,        # n
        $msgData)   = unpack("C C n a*", $message);

    if ($msgType == 0x0C) { # is ServerKeyExchange
        # get info about the session cipher and prepare parameter $keyExchange
        # for parseServerKeyExchange()
        my $keyExchange = $cipher;
        _trace1("_get_dhparam: cipher: $keyExchange");
        $keyExchange =~ s/^((?:EC)?DHE?)_anon.*/A$1/;   # DHE_anon -> EDH, ECDHE_anon -> AECDH, DHE_anon -> ADHE
        $keyExchange =~ s/^((?:EC)?DH)E.*/E$1/;         # DHE -> EDH, ECDHE -> EECDH
        $keyExchange =~ s/^(?:E|A|EA)((?:EC)?DH).*/$1/; # EDH -> DH, ADH -> DH, EECDH -> ECDH
        _trace1(" _get_dhparam: keyExchange (DH or ECDH) = $keyExchange");
        # get length of 'dh_parameter' manually from '-msg' data if the
        # 'session cipher' uses a keyExchange with DHE and DH_anon
        # (according RFC2246/RFC5246: sections 7.4.3)
        $dh = Net::SSLhello::parseServerKeyExchange($keyExchange, $msgLen, $msgData);
    }

    chomp $dh;
    _trace("_get_dhparam(){ ServerKeyExchange\t= $dh }");
    return $dh;
}; # _get_dhparam

sub get_openssl_version($) {
    #? call external openssl executable to retrive its version
    # we do a simple call, no checks, should work on all platforms
    # get something like: OpenSSL 1.0.1k 8 Jan 2015
    my $cmd  = shift;
    my $data = qx($cmd version);
    ## $data = Net::SSLinfo::do_openssl('version', "", ""); # should work too
    chomp $data;
    _trace("get_openssl_version: $data");
    $data =~ s#^.*?(\d+(?:\.\d+)*).*$#$1#; # get version number without letters
    _trace("get_openssl_version()\t= $data");
    return $data;
} # get_openssl_version

sub _usesocket($$$$) {
    # return cipher accepted by SSL connection
    # should return the targets default cipher if no ciphers passed in
    # NOTE that this is used to check for supported ciphers only, hence no
    # need for sophisticated options in new()
    # $ciphers must be colon (:) separated list
    my ($ssl, $host, $port, $ciphers) = @_;
    my $sni = ($cfg{'usesni'} == 1) ? $host : "";
    my $cipher = "";
    my $sslsocket = undef;
    # TODO: dirty hack to avoid perl error like:
    #    Use of uninitialized value in subroutine entry at /usr/share/perl5/IO/Socket/SSL.pm line 562.
    # which may occour if Net::SSLeay was not build properly with support for
    # these protocols. We only check for SSLv2 and SSLv3 as the *TLSX doesn't
    # produce such arnings. Sigh.
    _trace1("_usesocket($host, $port, $ciphers){");
    if (($ssl eq "SSLv2") && (! defined &Net::SSLeay::CTX_v2_new)) {
        _warn("SSL version '$ssl': not supported by Net::SSLeay");
        return "";
    }
    if (($ssl eq "SSLv3") && (! defined &Net::SSLeay::CTX_v3_new)) {
        _warn("SSL version '$ssl': not supported by Net::SSLeay");
        return "";
    }
    # FIXME: use Net::SSLeay instead of IO::Socket::SSL
    #if (IO::Socket::SSL->can_ecdh() == 1) {}
    if (eval {  # FIXME: use something better than eval()
        # TODO: eval necessary to avoid perl error like:
        #   invalid SSL_version specified at /usr/share/perl5/IO/Socket/SSL.pm line 492.
        # TODO: SSL_hostname does not support IPs (at least up to 1.88); check done in IO::Socket::SSL
        unless (($cfg{'starttls'}) || (($cfg{'proxyhost'})&&($cfg{'proxyport'}))) {
            # no proxy and not starttls
            $sslsocket = IO::Socket::SSL->new(
                PeerAddr        => $host,
                PeerPort        => $port,
                Proto           => "tcp",
                Timeout         => $cfg{'timeout'},
                SSL_hostname    => $sni,    # for SNI
                SSL_verify_mode => 0x0,     # SSL_VERIFY_NONE => Net::SSLeay::VERIFY_NONE(); # 0
                SSL_ca_file     => undef,   # see man IO::Socket::SSL ..
                SSL_ca_path     => undef,   # .. newer versions are smarter and accept ''
                SSL_version     => $ssl,    # default is SSLv23
                SSL_check_crl   => 0,       # do not check CRL
                SSL_cipher_list => $ciphers,
             # SSL_cipher_list => "$ciphers eNULL",
                #SSL_ecdh_curve  => "prime256v1", # default is prime256v1
            );
        } else {
            # proxy or starttls
            _trace1("_usesocket: using 'Net::SSLhello'");
            $sslsocket = Net::SSLhello::openTcpSSLconnection($host, $port);
            if ((!defined ($sslsocket)) || ($@)) { # No SSL Connection 
                $@ = " Did not get a valid SSL-Socket from Function openTcpSSLconnection -> Fatal Exit" unless ($@);
                _warn("_usesocket: openTcpSSLconnection() failed: $@\n"); 
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
                  SSL_version     => $ssl,    # default is SSLv23
                  SSL_cipher_list => $ciphers,
                ) or do {
                    _trace1("_usesocket: ssl handshake failed: $!");
                    return "";
                };
            }
        }
    }) {    # eval succeded
        if ($sslsocket) {
            $cipher = $sslsocket->get_cipher();
            $sslsocket->close(SSL_ctx_free => 1);
        }
    }
    # else  # connect failed, cipher not accepted, or error in IO::Socket::SSL
    _trace1("_usesocket()\t= $cipher }");
    return $cipher;
} # _usesocket

sub _useopenssl($$$$) {
    # return cipher accepted by SSL connection
    # should return the targets default cipher if no ciphers passed in
    # $ciphers must be colon (:) separated list
    my ($ssl, $host, $port, $ciphers) = @_;
    my $msg  =  $cfg{'openssl_msg'};
    my $sni  = ($cfg{'usesni'} == 1) ? "-servername $host" : "";
    $ciphers = ($ciphers      eq "") ? "" : "-cipher $ciphers";
    _trace1("_useopenssl($ssl, $host, $port, $ciphers)"); # no { in comment here
    $ssl = $cfg{'openssl_option_map'}->{$ssl};
    my $data = Net::SSLinfo::do_openssl("s_client $ssl $sni $msg $ciphers -connect", $host, $port);
    # we may get for success:
    #   New, TLSv1/SSLv3, Cipher is DES-CBC3-SHA
    # also possible would be Cipher line from:
    #   SSL-Session:
    #       Cipher    : DES-CBC3-SHA
    _trace2("_useopenssl: data #{ $data }");
    return "" if ($data =~ m#New,.*?Cipher is .?NONE#);

    my $cipher = $data;
    if ($cipher =~ m#New, [A-Za-z0-9/.,-]+ Cipher is#) {
        $cipher =~ s#^.*[\r\n]+New,\s*##s;
        $cipher =~ s#[A-Za-z0-9/.,-]+ Cipher is\s*([^\r\n]*).*#$1#s;
        my $dh  = _get_dhparam($cipher, $data);
        _trace1("_useopenssl()\t= $cipher $dh }");
        return wantarray ? ($cipher, $dh) : $cipher;
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
    return "" if ($data =~ m#SSL routines.*(?:handshake failure|null ssl method passed|no ciphers? (?:available|match))#);
    if ($data =~ m#^\s*$#) {
        _warn("SSL version '$ssl': empty result from openssl");
    } else {
        _warn("SSL version '$ssl': unknown result from openssl");
    }
    _trace2("_useopenssl: #{ $data }");
    if ($cfg{'verbose'} > 0) {
        _v_print("_useopenssl: Net::SSLinfo::do_openssl() #{\n$data\n#}");
    } else {
        print STR_HINT, "use options like: --v --trace";
    }

    return "";
} # _useopenssl

sub _get_default($$$) {
    # return (default) offered cipher from target
    my ($ssl, $host, $port) = @_;
    my $cipher = "";
    _trace("_get_default($ssl, $host, $port){");   # TODO: rejoin the trace?
    $cfg{'done'}->{'checkdefault'}++;
#   #if (1 == _is_call('cipher-socket')) {}
    if (0 == $cmd{'extciphers'}) {
        $cipher = _usesocket( $ssl, $host, $port, "");
    } else { # force openssl
        $cipher = _useopenssl($ssl, $host, $port, "");
    }
    if ($cipher =~ m#^\s*$#) {
        # TODO: SSLv2 is special, see _usesocket "dirty hack"
        if ($ssl =~ m/SSLv[2]/) {
            _warn("SSL version '$ssl': cannot get default cipher; ignored");
        } else {
            _v_print("SSL version '$ssl': cannot get default cipher; ignored");
        }
    }
    _trace("_get_default()\t= $cipher }"); # TODO: trace a bit late
    return $cipher;
} # _get_default

sub ciphers_get($$$$) {
    #? test target if given ciphers are accepted, returns array of accepted ciphers
    my $ssl     = shift;
    my $host    = shift;
    my $port    = shift;
    my @ciphers = @{$_[0]};# ciphers to be checked

    _trace("ciphers_get($ssl, $host, $port, @ciphers){");
    my @res     = ();      # return accepted ciphers
    foreach my $c (@ciphers) {
    #    _v_print("check cipher: $ssl:$c");
        my $supported = "";
#        if (1 == _is_call('cipher-socket')) {
        if (0 == $cmd{'extciphers'}) {
            if (0 >= $cfg{'use_md5cipher'}) {
                # Net::SSLeay:SSL supports *MD5 for SSLv2 only
                # detailled description see OPTION  --no-md5-cipher
                next if (($ssl ne "SSLv2") && ($c =~ m/MD5/));
            }
            $supported = _usesocket( $ssl, $host, $port, $c);
        } else { # force openssl
            $supported = _useopenssl($ssl, $host, $port, $c);
        }
        push(@res, $c) if ($supported !~ /^\s*$/);
    } # foreach @ciphers
    _trace("ciphers_get()\t= " . $#res . " @res }");
    return @res;
} # ciphers_get

sub checkcipher($$) {
    #? test given cipher and add result to %checks and %prot
    my ($ssl, $c) = @_;
    my $risk = get_cipher_sec($c);
    # following checks add the "not compliant" or vulnerable ciphers

    # check weak ciphers
    $checks{'null'}->{val}      .= _prot_cipher($ssl, $c) if ($c =~ /NULL/);
    $checks{'adh'}->{val}       .= _prot_cipher($ssl, $c) if ($c =~ /$cfg{'regex'}->{'ADHorDHA'}/);
    $checks{'edh'}->{val}       .= _prot_cipher($ssl, $c) if ($c =~ /$cfg{'regex'}->{'DHEorEDH'}/);
    $checks{'export'}->{val}    .= _prot_cipher($ssl, $c) if ($c =~ /$cfg{'regex'}->{'EXPORT'}/);
    $checks{'rc4_cipher'}->{val}.= _prot_cipher($ssl, $c) if ($c =~ /$cfg{'regex'}->{'RC4orARC4'}/);
# TODO: lesen: http://www.golem.de/news/mindeststandards-bsi-haelt-sich-nicht-an-eigene-empfehlung-1310-102042.html
    # check compliance
    $checks{'ism'}->{val}       .= _prot_cipher($ssl, $c) if ($c =~ /$cfg{'regex'}->{'notISM'}/);
    $checks{'pci'}->{val}       .= _prot_cipher($ssl, $c) if ("" ne _ispci( $ssl, $c));
    $checks{'fips'}->{val}      .= _prot_cipher($ssl, $c) if ("" ne _isfips($ssl, $c));
#   $checks{'rfc7525'}->{val}   .= _prot_cipher($ssl, $c) if ("" ne _isrfc7525($ssl, $c));
    $checks{'tr-02102'}->{val}  .= _prot_cipher($ssl, $c) if ("" ne _istr02102($ssl, $c));
    $checks{'tr-03116+'}->{val} .= _prot_cipher($ssl, $c) if ("" ne _istr03116_strict($ssl, $c));
    $checks{'tr-03116-'}->{val} .= _prot_cipher($ssl, $c) if ("" ne _istr03116_lazy($ssl, $c));
    # check attacks
    $checks{'rc4'}->{val}        = $checks{'rc4_cipher'}->{val}; # these are the same checks
    $checks{'beast'}->{val}     .= _prot_cipher($ssl, $c) if ("" ne _isbeast($ssl, $c));
    $checks{'breach'}->{val}    .= _prot_cipher($ssl, $c) if ("" ne _isbreach($c));
    $checks{'freak'}->{val}     .= _prot_cipher($ssl, $c) if ("" ne _isfreak($ssl, $c));
    $checks{'lucky13'}->{val}   .= _prot_cipher($ssl, $c) if ("" ne _islucky($c));
    $checks{'sloth'}->{val}     .= _prot_cipher($ssl, $c) if ("" ne _issloth($ssl, $c));
    push(@{$prot{$ssl}->{'pfs_ciphers'}}, $c) if ("" eq _ispfs($ssl, $c));  # add PFS cipher
    # counters
    $prot{$ssl}->{'-?-'}++      if ($risk =~ /-\?-/);       # private marker
    $prot{$ssl}->{'WEAK'}++     if ($risk =~ /WEAK/i);
    $prot{$ssl}->{'LOW'}++      if ($risk =~ /LOW/i);
    $prot{$ssl}->{'MEDIUM'}++   if ($risk =~ /MEDIUM/i);
    $prot{$ssl}->{'HIGH'}++     if ($risk =~ /HIGH/i);
} # checkcipher

sub checkciphers($$) {
    #? test target if given ciphers are accepted, results stored in global %checks
    # checks are done with information from @results
    my ($host, $port) = @_;     # not yet used

    _y_CMD("checkciphers() " . $cfg{'done'}->{'checkciphers'});
    $cfg{'done'}->{'checkciphers'}++;
    return if ($cfg{'done'}->{'checkciphers'} > 1);
    _trace("checkciphers($host, $port){");

    my $ssl     = "";
    my $cipher  = "";
    my %hasecdsa;   # ECDHE-ECDSA is mandatory for TR-02102-2, see 3.2.3
    my %hasrsa  ;   # ECDHE-RSA   is mandatory for TR-02102-2, see 3.2.3
    foreach my $c (@results) {  # check all accepted ciphers
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

    # BEAST check
    if ($prot{'SSLv3'}->{'cnt'} <= 0) {
        # if SSLv3 was disabled, check for BEAST is incomplete; inform about that
        $checks{'beast'}->{val} .= " " . _subst($text{'disabled'}, "--no-SSLv3");
    }
    $checks{'breach'}->{val}     = "<<NOT YET IMPLEMENTED>>";
    foreach $ssl (@{$cfg{'version'}}) { # check all SSL versions
        $hasrsa{$ssl}  = 0 if (!defined $hasrsa{$ssl});     # keep perl silent
        $hasecdsa{$ssl}= 0 if (!defined $hasecdsa{$ssl});   #  "
        # TR-02102-2, see 3.2.3
        if ($prot{$ssl}->{'cnt'} > 0) { # checks do not make sense if there're no ciphers
            $checks{'tr-02102'}->{val}  .= _prot_cipher($ssl, $text{'miss-RSA'})   if ($hasrsa{$ssl}   != 1);
            $checks{'tr-02102'}->{val}  .= _prot_cipher($ssl, $text{'miss-ECDSA'}) if ($hasecdsa{$ssl} != 1);
            $checks{'tr-03116+'}->{val} .= $checks{'tr-02102'}->{val};  # same as TR-02102
            $checks{'tr-03116-'}->{val} .= $checks{'tr-02102'}->{val};
        }
        $checks{'cnt_ciphers'}->{val}   += $prot{$ssl}->{'cnt'};    # need this with cnt_ prefix
    }
    $checks{'edh'}->{val} = "" if ($checks{'edh'}->{val} ne "");    # good if we have them

    # 'sslversion' returns protocol as used in our data structure (like TLSv12)
    # 'session_protocol' retruns string used by openssl (like TLSv1.2)
    # we need our well known string, hence 'sslversion'
    $ssl    = $data{'sslversion'}->{val}($host, $port); # get selected protocol
    $cipher = $data{'selected'}->{val}($host, $port);   # get selected cipher
    $checks{'pfs_cipherall'}->{val} = " " if ($prot{$ssl}->{'cnt'} > $#{$prot{$ssl}->{'pfs_ciphers'}});
    #$checks{'pfs_cipher'}->{val} # done in checkdest()
    _trace("checkciphers() }");
} # checkciphers

sub check_dh($$) {
    #? check if target is vulnerable to Logjam attack
    my ($host, $port) = @_;
    _y_CMD("check_dh() ". $cfg{'done'}->{'check_dh'});
    $cfg{'done'}->{'check_dh'}++;
    return if ($cfg{'done'}->{'check_dh'} > 1);

    checkciphers($host, $port); # need EXPORT ciphers

    # Logjam check is a bit ugly: DH Parameter may be missing
    # TODO: implement own check for DH parameters instead relying on openssl
    my $txt = $data{'dh_parameter'}->{val}($host);
    my $exp = $checks{'logjam'}->{val};
    if ($txt eq "") {
        $txt = "<<openssl did not return DH Paramter>>";
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
} # check_dh

sub checkbleed($$) {
    #? check if target supports TLS extension 15 (hearbeat)
    my ($host, $port) = @_;
    _y_CMD("checkbleed() ". $cfg{'done'}->{'checkbleed'});
    $cfg{'done'}->{'checkbleed'}++;
    return if ($cfg{'done'}->{'checkbleed'} > 1);
    $checks{'heartbleed'}->{val}  = _isbleed($host, $port);
} # checkbleed

sub checkdates($$) {
    # check validation of certificate's before and after date
    my ($host, $port) = @_;
    _y_CMD("checkdates() " . $cfg{'done'}->{'checkdates'});
    $cfg{'done'}->{'checkdates'}++;
    return if ($cfg{'done'}->{'checkdates'} > 1);
       #
       # Note about calculating dates:
       # calculation should be done without using additional perl modules like
       # Time::Local, Date::Calc, Date::Manip, ...
       # Hence we convert the date given by the certificate's before and after
       # value to the format  YYYYMMDD. The format given in the certificate is
       # always GMT and in fixed form:  MMM DD hh:mm:ss YYYY GMT. So a split()
       # gives year and day as integer. Just the month is a string, which need
       # to be converted to an integer using the map() funtion on @mon array.
       # The same format is used for the current date given by gmtime(), but
       # convertion is much simpler as no strings exist here.
    my @now = gmtime(time);
    my $now = sprintf("%4d%02d%02d ", $now[5]+1900, $now[4]+1, $now[3]);
    my @mon = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
    my $m   = 0;
    my @since = split(/ +/, $data{'before'}->{val}($host));
    my @until = split(/ +/, $data{'after'} ->{val}($host));
    my $s_mon = 0; my $u_mon = 0;
       map({$m++; $s_mon=$m if/$since[0]/} @mon); $m = 0;
       map({$m++; $u_mon=$m if/$until[0]/} @mon); $m = 0;
    my $start = sprintf("%s%02s%02s", $since[3], $s_mon, $since[1]);
    my $end   = sprintf("%s%02s%02s", $until[3], $u_mon, $until[1]);
    # end date magic, do checks ..
    $checks{'dates'}->{val}     =          $data{'before'}->{val}($host) if ($now < $start);
    $checks{'dates'}->{val}    .= " .. " . $data{'after'} ->{val}($host) if ($now > $end);
    $checks{'expired'}->{val}   =          $data{'after'} ->{val}($host) if ($now > $end);
    $data{'valid-years'}->{val}     = ($until[3]       -  $since[3]);
    $data{'valid-months'}->{val}    = ($until[3] * 12) - ($since[3] * 12) + $u_mon - $s_mon;
    $data{'valid-days'}->{val}      = ($data{'valid-years'}->{val}  *  5) + ($data{'valid-months'}->{val} * 30); # approximately
    $data{'valid-days'}->{val}      = ($until[1] - $since[1]) if ($data{'valid-days'}->{val} < 60); # more accurate
    _trace("checkdates: start, now, end: : $start, $now, $end");
    _trace("checkdates: valid:       " . $checks{'dates'}->{val});
    _trace("checkdates: valid-years: " . $data{'valid-years'}->{val});
    _trace("checkdates: valid-month: " . $data{'valid-months'}->{val} . "  = ($until[3]*12) - ($since[3]*12) + $u_mon - $s_mon");
    _trace("checkdates: valid-days:  " . $data{'valid-days'}->{val}   . "  = (" . $data{'valid-years'}->{val} . "*5) + (" . $data{'valid-months'}->{val} . "*30)");
} # checkdates

sub checkcert($$) {
    #? check certificate settings
    my ($host, $port) = @_;
    my ($value, $label, $subject, $txt);
    _y_CMD("checkcert() " . $cfg{'done'}->{'checkcert'});
    $cfg{'done'}->{'checkcert'}++;
    return if ($cfg{'done'}->{'checkcert'} > 1);

    # wildcards (and some sizes)
    _getwilds($host, $port);
    # $checks{'certfqdn'}->{val} ... done in checksni()

    $checks{'rootcert'}->{val}  = $data{'issuer'}->{val}($host) if ($data{'subject'}->{val}($host) eq $data{'issuer'}->{val}($host));
    #dbx# _dbx "S " .$data{'subject'}->{val}($host);
    #dbx# _dbx "S " .$data{'issuer'}->{val}($host);

    $checks{'ocsp'}->{val}      = " " if ($data{'ocsp_uri'}->{val}($host) eq "");
    $checks{'cps'}->{val}       = " " if ($data{'ext_cps'}->{val}($host) eq "");
    $checks{'crl'}->{val}       = " " if ($data{'ext_crl'}->{val}($host) eq "");
    $value = $data{'ext_constraints'}->{val}($host);
    $checks{'constraints'}->{val}   = " "    if ($value eq "");
    $checks{'constraints'}->{val}   = $value if ($value !~ m/CA:FALSE/i);
    # TODO: more checks necessary:
    #    KeyUsage field must set keyCertSign and/or the BasicConstraints field has the CA attribute set TRUE.

    foreach $label (qw(cn subject issuer email aux ocsp_uri altname)) {
        $value = $data{$label}->{val}($host);
        if ($value ne "") {
            $checks{'nonprint'}{val} .= " $label" if ($value =~ m/[\x00-\x1f\x7f-\xff]+/); # m/[:^print:]/);
            $checks{'crnlnull'}{val} .= " $label" if ($value =~ m/[\r\n\t\v\0]+/);
        }
    }

    # certificate
    if ($cfg{'verbose'} > 0) { # TODO
        foreach $label (qw(verify selfsigned)) {
            #dbx# _dbx "$label : $value #";
            $value = $data{$label}->{val}($host);
            $checks{$label}->{val}   = $value if ($value eq "");

# FIXME:  $data{'verify'} $data{'error_verify'} $data{'error_depth'}
#   if (_is_do('verify')) {
#       print "";
#       print "Hostname validity:       "      . Net::SSLinfo::verify_hostname($host, $port);
#       print "Alternate name validity: "      . Net::SSLinfo::verify_altname($host, $port);
#   }
#
#   if (_is_do('altname')) {
#       print "";
#       print "Certificate AltNames:    "      . Net::SSLinfo::altname($host, $port);
#       print "Alternate name validity: "      . Net::SSLinfo::verify_altname($host, $port);
#   }
        }
    }
    $checks{'selfsigned'}    ->{val} = $data{'selfsigned'}->{val}($host);
    $checks{'fp_not_md5'}    ->{val} = $data{'fingerprint'} if ('MD5' eq $data{'fingerprint'});
    $value = $data{'signame'}->{val}($host);
    $checks{'sha2signature'} ->{val} = $value if ($value !~ m/^$cfg{'regex'}->{'SHA2'}/);
    $checks{'sig_encryption'}->{val} = $value if ($value !~ m/$cfg{'regex'}->{'encryption'}/i);
    $checks{'sig_enc_known'} ->{val} = $value if ($value !~ m/^$cfg{'regex'}->{'encryption_ok'}|$cfg{'regex'}->{'encryption_no'}$/i);
    $value = $data{'pubkey_algorithm'}->{val}($host);
    $checks{'pub_encryption'}->{val} = $value if ($value !~ m/$cfg{'regex'}->{'encryption'}/i);
    $checks{'pub_enc_known'} ->{val} = $value if ($value !~ m/^$cfg{'regex'}->{'encryption_ok'}|$cfg{'regex'}->{'encryption_no'}$/i);

# TODO: ocsp_uri pruefen; Soft-Fail, Hard-Fail

    # valid characters (most likely only relevant for EV)
    #_dbx "EV: regex:" . $cfg{'regex'}->{'notEV-chars'};
    foreach $label (qw(cn subject altname extensions ext_crl ocsp_uri)) { # CRL
        # also (should already be part of others): CN, O, U
        $subject =  $data{$label}->{val}($host);
        $subject =~ s#[\r\n]##g;         # CR and NL are most likely added by openssl
        if ($subject =~ m!$cfg{'regex'}->{'notEV-chars'}!) {
            $txt = _subst($text{'cert-chars'}, $label);
            $checks{'ev-chars'}->{val} .= $txt;
            $checks{'ev+'}->{val}      .= $txt;
            $checks{'ev-'}->{val}      .= $txt;
            $checks{'dv'}->{val}       .= $txt;
             if ($cfg{'verbose'} > 0) {
                 $subject =~ s#($cfg{'regex'}->{'EV-chars'}+)##msg;
                 _v2print("EV:  wrong characters in $label: $subject" . "\n");
             }
        }
    }

# TODO: check: serialNumber: Positive number up to a maximum of 20 octets.
# TODO: check: Signature: Must be the same OID as that defined in SignatureAlgorithm below.
# TODO: check: Version
# TODO: check: validity (aka dates)
# TODO: check: Issuer
#        Only CN=, C=, ST=, O=, OU= and serialNumber= must be supported the rest are optional 
# TODO: check: Subject
#        The subject field can be empty in which case the entity being authenticated is defined in the subjectAltName.

} # checkcert

sub checksni($$) {
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
} # checksni

sub checksizes($$) {
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
    $checks{'len_subject'}  ->{val} = length($data{'subject'}->{val}($host));
    $checks{'len_issuer'}   ->{val} = length($data{'issuer'}->{val}($host));
    $checks{'len_cps'}      ->{val} = length($data{'ext_cps'}->{val}($host));
    $checks{'len_crl'}      ->{val} = length($data{'ext_crl'}->{val}($host));
    #$checks{'len_crl_data'} ->{val} = length($data{'crl'}->{val}($host));
    $checks{'len_ocsp'}     ->{val} = length($data{'ocsp_uri'}->{val}($host));
    #$checks{'len_oids'}     ->{val} = length($data{'oids'}->{val}($host));
    $checks{'len_sernumber'}->{val} = int(length($data{'serial_hex'}->{val}($host)) / 2); # value are hex octets
        # Note: RFC5280 limits to 20 digit (integer), which is hard to check
        #       with the hex value, anyway it should not be more than 8 bytes
    $value = $data{'modulus_len'}->{val}($host);
    $checks{'len_publickey'}->{val} = (($value =~ m/^\s*$/) ? 0 : $value); # missing without openssl
    $value = $data{'modulus_exponent'}->{val}($host);  # i.e. 65537 (0x10001) or prime256v1
    if ($value =~ m/prime/i) {  # public key uses EC with primes
        $checks{'modulus_exp_size'}->{val}  = "<<N/A $value>>";
        $checks{'modulus_size'}->{val}      = "<<N/A $value>>";
    } else  {                   # only traditional exponent needs to be checked
        $value =~ s/^(\d+).*/$1/;
        $checks{'modulus_exp_size'}->{val}  = $value if ($value > 65536);
        $value = $data{'modulus'}->{val}($host); # value are hex digits
        $checks{'modulus_size'} ->{val} = length($value) * 4 if ((length($value) * 4) > 16384);
    }
    $value = $data{'serial_int'}->{val}($host);
    #$value = 0 if($value =~ m/^\s*$/); # if value is empty, we might get: Argument "" isn't numeric in int
    $checks{'sernumber'}    ->{val} = length($value) ." > 20" if (length($value) > 20);
    $value = $data{'sigkey_len'}->{val}($host);
    $checks{'len_sigdump'}  ->{val} = (($value =~ m/^\s*$/) ? 0 : $value); # missing without openssl
} # checksizes

sub check02102($$) {
    #? check if target is compliant to BSI TR-02102-2
    # assumes that checkssl() already done
    my ($host, $port) = @_;
    _y_CMD("check02102() " . $cfg{'done'}->{'check02102'});
    $cfg{'done'}->{'check02102'}++;
    return if ($cfg{'done'}->{'check02102'} > 1);
    my $txt = "";
    #
    # description (see CHECK in pod below) ...
    # lines starting with #! are headlines from TR-02102-2

    # All checks according ciphers already done in checkciphers() and stored
    # in $checks{'tr-02102'}. We need to do checks according certificate and
    # protocol and fill other %checks values according requirements.

    #! TR-02102-2 3.2.1 Empfohlene Cipher Suites
    #! TR-02102-2 3.2.2 Übergangsregelungen
    #! TR-02102-2 3.2.3 Mindestanforderungen für Interoperabilität
    $checks{'bsi-tr-02102+'}->{val} = $checks{'tr-02102'}->{val}; # cipher checks are already done
    $checks{'bsi-tr-02102-'}->{val} = $checks{'tr-02102'}->{val}; # .. for lazy check, ciphers are enough

    #! TR-02102-2 3.3 Session Renegotation
    $checks{'bsi-tr-02102+'}->{val}.= $text{'no-reneg'}   if ($checks{'renegotiation'}->{val} ne "");

    #! TR-02102-2 3.4 Zertifikate und Zertifikatsverifikation
    $txt = _subst($text{'cert-valid'}, $data{'valid-years'}->{val});
    $checks{'bsi-tr-02102+'}->{val}.= $txt                if ($data{'valid-years'}->{val} > 3);
    $checks{'bsi-tr-02102+'}->{val}.= $text{'cert-dates'} if ($checks{'dates'}->{val} ne "");
    $checks{'bsi-tr-02102+'}->{val}.= _subst($text{'missing'}, 'CRL')  if ($checks{'crl'}->{val} ne "");
    $checks{'bsi-tr-02102+'}->{val}.= _subst($text{'missing'}, 'AIA')  if ($data{'ext_authority'}->{val}($host) eq "");
    $checks{'bsi-tr-02102+'}->{val}.= _subst($text{'missing'}, 'OCSP') if ($data{'ocsp_uri'}->{val}($host)  eq "");
    $checks{'bsi-tr-02102+'}->{val}.= _subst($text{'wildcards'}, $checks{'wildcard'}->{val}) if ($checks{'wildcard'}->{val} ne "");

    #! TR-02102-2 3.5 Domainparameter und Schlüssellängen
# FIXME:

    #! TR-02102-2 3.6 Schlüsselspeicherung
    #! TR-02102-2 3.7 Umgang mit Ephemeralschlüsseln
    #! TR-02102-2 3.8 Zufallszahlen
        # these checks are not possible from remote

    # FIXME: certificate (chain) validation check
    # TODO: cipher bit length check

} # check02102

sub check03116($$) {
    #? check if target is compliant to BSI TR-03116-4
    # BSI TR-03116-4 is similar to BSI TR-02102-2
    _y_CMD("check03116() " . $cfg{'done'}->{'check03116'});
    $cfg{'done'}->{'check03116'}++;
    return if ($cfg{'done'}->{'check03116'} > 1);
    my $txt = "";

    # All checks according ciphers already done in checkciphers() and stored
    # in $checks{'tr-02102'}. We need to do checks according certificate and
    # protocol and fill other %checks values according requirements.

    #! TR-03116-4 2.1.1 TLS-Versionen und Sessions
        # muss mindestens die TLS-Version 1.2 unterstützt werden
    #! TR-03116-4 2.1.2 Cipher Suites
    $checks{'bsi-tr-03116+'}->{val} = $checks{'tr-03116+'}->{val};
    $checks{'bsi-tr-03116-'}->{val} = $checks{'tr-03116-'}->{val};

    #! TR-03116-4 2.1.1 TLS-Versionen und Sessions
        # TLS Session darf eine Lebensdauer von 2 Tagen nicht überschreiten
    #! TR-03116-4 2.1.4.2 Encrypt-then-MAC-Extension
    #! TR-03116-4 2.1.4.3 OCSP-Stapling
    $checks{'bsi-tr-03116+'}->{val} .= _subst($text{'missing'}, 'OCSP') if ($data{'ocsp_uri'}->{val}($host)  eq "");

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
    $txt = _subst($text{'cert-valid'}, $data{'valid-years'}->{val}); # NOTE: 'valid-years' is special value
    $checks{'bsi-tr-03116+'}->{val} .= $txt                if ($data{'valid-years'}->{val} > 3);
# FIXME: cert itself and CA-cert have different validity: 3 vs. 5 years
    $txt = $checks{'wildcard'}->{val};
    if (($data{'ext_crl'}->{val}($host) eq "") && ($data{'ext_authority'}->{val}($host) eq "")) {
        $checks{'bsi-tr-03116+'}->{val} .= _subst($text{'missing'}, 'AIA or CRL');
    }
# FIXME: need to verify provided CRL and OCSP
    $checks{'bsi-tr-03116+'}->{val} .= _subst($text{'wildcards'}, $txt) if ($txt ne "");
    # _getwilds() checks for CN and subjectAltname only, we need Subject also
    $txt = $data{'subject'}->{val}($host);
    $checks{'bsi-tr-03116+'}->{val} .= _subst($text{'wildcards'}, "Subject:$txt") if ($txt =~ m/[*]/);
# FIXME: need to check wildcards in all certificates

    #! TR-03116-4 4.1.3 Zertifikatsverifikation
        # * vollständige Prüfung der Zertifikatskette bis zu einem für die
        #   jeweilige Anwendung vertrauenswürdigen und als authentisch
        #   bekannten Vertrauensanker
# FIXME:
        # * Prüfung auf Gültigkeit (Ausstellungs- und Ablaufdatum)
        # * Rückrufprüfung aller Zertifikate
    $txt = $checks{'dates'}->{val};
    $checks{'bsi-tr-03116+'}->{val} .= _subst($text{'cert-dates'}, $txt) if ($txt ne "");
    $txt = $checks{'expired'}->{val};
    $checks{'bsi-tr-03116+'}->{val} .= _subst($text{'cert-valid'}, $txt) if ($txt ne "");

    #! TR-03116-4 4.1.4 Domainparameter und Schlüssellängen
        # ECDSA 224 Bit; DSA 2048 Bit; RSASSA-PSS 2048 Bit; alle SHA-224
        # empfohlene ECC:
        # * BrainpoolP224r1 3 , BrainpoolP256r1, BrainpoolP384r1, BrainpoolP512r1
        # * NIST Curve P-224, NIST Curve P-256, NIST Curve P-384, NIST Curve P-521
# FIXME:

    #! TR-03116-4 5.2 Zufallszahlen
        # these checks are not possible from remote

    $checks{'bsi-tr-03116-'}->{val} .= $checks{'bsi-tr-03116+'}->{val};

} # check03116

sub check6125($$) {
    #? check if certificate identifiers are RFC 6125 compliant
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

    # Note: wildcards itself are checked in   checkcert() _getwilds()
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
    foreach $txt (split(" ", $data{'altname'}->{val}($host))) {
        $txt  =~ s!.*:!!;        # strip prefix
        $val .= " <<6.4.2:altname $txt>>" if ($txt !~ m!$cfg{'regex'}->{'isDNS'}!);
        $val .= " <<6.4.3:altname $txt>>" if ($txt =~ m!$cfg{'regex'}->{'doublewild'}!);
        $val .= " <<6.4.3:altname $txt>>" if ($txt =~ m!$cfg{'regex'}->{'invalidwild'}!);
        $val .= " <<7.2.o:altname $txt>>" if ($txt =~ m!$cfg{'regex'}->{'invalidIDN'}!);
        $val .= " <<7.3:altname $txt>>"   if ($txt =~ m!$cfg{'regex'}->{'isIDN'}!);
    }
    $checks{'rfc6125_names'}->{val} = $val;

} # check6125

sub check7525($$) {
    #? check if target is RFC 7525 compliant
    _y_CMD("check7525() " . $cfg{'done'}->{'check7525'});
    $cfg{'done'}->{'check7525'}++;
    return if ($cfg{'done'}->{'check7525'} > 1);

    #from: https://www.rfc-editor.org/rfc/rfc7525.txt
    # 3.1.1.  SSL/TLS Protocol Versions
    #    Implementations MUST support TLS 1.2 [RFC5246] and MUST prefer to
    #    negotiate TLS version 1.2 over earlier versions of TLS.
    #  ==> done in _isrfc7525
    #    Implementations SHOULD NOT negotiate TLS version 1.1 [RFC4346];
    #    the only exception is when no higher version is available in the
    #    negotiation.
    # TODO for lazy check
    #
    # 3.1.2.  DTLS Protocol Versions
    #    Implementations SHOULD NOT negotiate DTLS version 1.0 [RFC4347].
    #    Implementations MUST support and MUST prefer to negotiate DTLS
    #    version 1.2 [RFC6347].
    # TODO o-saft currently (5/2015) does not support DTLSv1x
    #
    # 3.2.  Strict TLS
    #    ... TLS-protected traffic (such as STARTTLS),
    #    clients and servers SHOULD prefer strict TLS configuration.
    #
    #    HTTP client and server implementations MUST support the HTTP
    #    Strict Transport Security (HSTS) header [RFC6797]
    #
    # 3.3.  Compression
    #    ... implementations and deployments SHOULD
    #    disable TLS-level compression (Section 6.2.2 of [RFC5246]), unless
    #    the application protocol in question has been shown not to be open to
    #    such attacks.
    #
    # 3.4.  TLS Session Resumption
    #    ... the resumption information MUST be authenticated and encrypted ..
    #    A strong cipher suite MUST be used when encrypting the ticket (as
    #    least as strong as the main TLS cipher suite).
    #    Ticket keys MUST be changed regularly, e.g., once every week, ...
    #    For similar reasons, session ticket validity SHOULD be limited to
    #    a reasonable duration (e.g., half as long as ticket key validity).
    # TODO 
    #
    # 3.5.  TLS Renegotiation
    #    ... both clients and servers MUST implement the renegotiation_info
    #    extension, as defined in [RFC5746].
    #
    # 3.6.  Server Name Indication
    #    TLS implementations MUST support the Server Name Indication (SNI)
    #
    # 4.  Recommendations: Cipher Suites
    # 4.1.  General Guidelines
    #    Implementations MUST NOT negotiate the cipher suites with NULL encryption.
    #    Implementations MUST NOT negotiate RC4 cipher suites.
    #    Implementations MUST NOT negotiate cipher suites offering less
    #    than 112 bits of security, ...
    #  ==> done in _isrfc7525
    #    Implementations SHOULD NOT negotiate cipher suites that use
    #    algorithms offering less than 128 bits of security.
    # TODO for lazy check
    #    Implementations SHOULD NOT negotiate cipher suites based on RSA
    #    key transport, a.k.a. "static RSA".
    #  ==> done in _isrfc7525
    #    Implementations MUST support and prefer to negotiate cipher suites
    #    offering forward secrecy, ...
    #  ==> done in _isrfc7525
    #
    # 4.2.  Recommended Cipher Suites
    #    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    #    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    #  ==> done in _isrfc7525
    #
    # 4.3.  Public Key Length
    #    ... DH key lengths of at least 2048 bits are RECOMMENDED.
    #    ... Curves of less than 192 bits SHOULD NOT be used.
    # TODO 
    #
    # 4.5.  Truncated HMAC
    #    Implementations MUST NOT use the Truncated HMAC extension, defined in
    #    Section 7 of [RFC6066].
    # TODO 
    #
    # 6.  Security Considerations
    # 6.1.  Host Name Validation
    #    If the host name is discovered indirectly and in an insecure manner
    #    (e.g., by an insecure DNS query for an MX or SRV record), it SHOULD
    #    NOT be used as a reference identifier [RFC6125] even when it matches
    #    the presented certificate.  This proviso does not apply if the host
    #    name is discovered securely (for further discussion, see [DANE-SRV]
    #    and [DANE-SMTP]).
    # TODO 
    #
    # 6.3.  Forward Secrecy
    #    ... therefore advocates strict use of forward-secrecy-only ciphers.
    #
    # 6.4.  Diffie-Hellman Exponent Reuse
    #
    # 6.5.  Certificate Revocation
    #    ... servers SHOULD support the following as a best practice
    #    OCSP [RFC6960]
    #    The OCSP stapling extension defined in [RFC6961]
    #
    my $txt = "";
} # check7525

sub checkdv($$) {
    #? check if certificate is DV-SSL
    my ($host, $port) = @_;
    _y_CMD("checkdv() "   . $cfg{'done'}->{'checkdv'});
    $cfg{'done'}->{'checkdv'}++;
    return if ($cfg{'done'}->{'checkdv'} > 1);
    #
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

    # required CN=
    if ($cn =~ m/^\s*$/) {
        $checks{'dv'}->{val} .= _subst($text{'missing'}, "Common Name");
        return; # .. as all other checks will fail too now
    }

    # CN= in subject or subjectAltname
    if (($subject !~ m#/$cfg{'regex'}->{$oid}=([^/\n]*)#)
    and ($altname !~ m#/$cfg{'regex'}->{$oid}=([^\s\n]*)#)) {
        $checks{'dv'}->{val} .= _subst($text{'missing'}, $data_oid{$oid}->{txt});
        return; # .. as ..
    }
    $txt = $1;  # $1 is matched FQDN

# TODO: %data_oid not yet used
    $data_oid{$oid}->{val} = $txt if ($txt !~ m/^\s*$/);
    $data_oid{$oid}->{val} = $cn  if ($cn  !~ m/^\s*$/);

    # there's no rule that CN's value must match the hostname, somehow ..
    # we check at least if subject or subjectAltname match hostname
    if ($txt ne $cn) {  # mismatch
        $checks{'dv'}->{val} .= $text{'EV-subject-CN'};
    }
    if ($txt ne $host) {# mismatch
        if (0 >= grep(/^DNS:$host$/, split(/[\s]/, $altname))) {
            $checks{'dv'}->{val} .= $text{'EV-subject-host'};
        }
    }

} # checkdv

sub checkev($$) {
    #? check if certificate is EV-SSL
    my ($host, $port) = @_;
    _y_CMD("checkev() "   . $cfg{'done'}->{'checkev'});
    $cfg{'done'}->{'checkev'}++;
    return if ($cfg{'done'}->{'checkev'} > 1);
    #
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
    #
    my $oid     = "";
    my $subject = $data{'subject'}->{val}($host);
    my $cn      = $data{'cn'}->{val}($host);
    my $alt     = $data{'altname'}->{val}($host);
    my $txt     = "";
    my $key     = "";

       # following checks work like:
       #   for each check add descriptive failture text (from %text)
       #   to $checks{'ev+'}->{val} if check fails

    checkdv($host, $port);
    $checks{'ev+'}->{val} = $checks{'dv'}->{val}; # wrong for DV then wrong for EV too

    # required OID
    foreach $oid (qw(
        1.3.6.1.4.1.311.60.2.1.1   1.3.6.1.4.1.311.60.2.1.3
        2.5.4.5    2.5.4.7   2.5.4.10   2.5.4.15
        )) {
        if ($subject =~ m#/$cfg{'regex'}->{$oid}=([^/\n]*)#) {
            $data_oid{$oid}->{val} = $1;
            _v2print("EV: " . $cfg{'regex'}->{$oid} . " = $1\n");
            #dbx# _dbx "L:$oid: $1";
        } else {
            _v2print("EV: " . _subst($text{'missing'}, $cfg{'regex'}->{$oid}) . "; required\n");
            $txt = _subst($text{'missing'}, $data_oid{$oid}->{txt});
            $checks{'ev+'}->{val} .= $txt;
            $checks{'ev-'}->{val} .= $txt;
        }
    }
    $oid = '1.3.6.1.4.1.311.60.2.1.2'; # or /ST=
    if ($subject !~ m#/$cfg{'regex'}->{$oid}=([^/\n]*)#) {
        $txt = _subst($text{'missing'}, $data_oid{$oid}->{txt});
        $checks{'ev+'}->{val} .= $txt;
        $oid = '2.5.4.8'; # or /ST=
        if ($subject =~ m#/$cfg{'regex'}->{'2.5.4.8'}=([^/\n]*)#) {
            $data_oid{$oid}->{val} = $1;
        } else {
            $checks{'ev-'}->{val} .= $txt;
            _v2print("EV: " . _subst($text{'missing'}, $cfg{'regex'}->{$oid}) . "; required\n");
        }
    }
    $oid = '2.5.4.9'; # may be missing
    if ($subject !~ m#/$cfg{'regex'}->{$oid}=([^/\n]*)#) {
        $txt = _subst($text{'missing'}, $data_oid{$oid}->{txt});
        $checks{'ev+'}->{val} .= $txt;
        _v2print("EV: " . $cfg{'regex'}->{$oid} . " = missing+\n");
        _v2print("EV: " . _subst($text{'missing'}, $cfg{'regex'}->{$oid}) . "; required\n");
    }
    # optional OID
    foreach $oid (qw(2.5.4.6 2.5.4.17)) {
    }
    if (64 < length($data_oid{'2.5.4.10'}->{val})) {
        $txt = _subst($text{'EV-large'}, "64 < " . $data_oid{$oid}->{txt});
        $checks{'ev+'}->{val} .= $txt;
        _v2print("EV: " . $txt . "\n");
    }
    # validity <27 months
    if ($data{'valid-months'}->{val} > 27) {
        $txt = _subst($text{'cert-valid'}, "27 < " . $data{'valid-months'}->{val});
        $checks{'ev+'}->{val} .= $txt;
        _v2print("EV: " . $txt . "\n");
    }
    # valid characters already don in checkcert()

    # TODO: wildcard no, SAN yes
    # TODO: cipher 2048 bit?
    # TODO: potential dangerous OID: '1.3.6.1.4.1.311.60.1.1'
    # TODO: Scoring: 100 EV+SGC; 80 EV; 70 EV-; 50 OV; 30 DV
} # checkev

sub checkroot($$) {
    #? check if certificate is root CA
    my ($host, $port) = @_;
    $cfg{'done'}->{'checkroot'}++;
    return if ($cfg{'done'}->{'checkroot'} > 1);

# some texts from: http://www.zytrax.com/tech/survival/ssl.html
# The term Certificate Authority is defined as being an entity which signs
# certificates in which the following are true:
#   * the issuer and subject fields are the same,
#   * the KeyUsage field has keyCertSign set
#   * and/or the basicConstraints field has the cA attribute set TRUE.
# Typically, in chained certificates the root CA certificate is the topmost
# in the chain but RFC 4210 defines a 'root CA' to be any issuer for which
# the end-entity, for example, the browser has a certificate which was obtained
# by a trusted out-of-band process. Since final authority for issuing any
# certificate rest with this CA the terms and conditions of any intermediate
# certificate may be modified by this entity.
#
# Subordinate Authority:
# may be marked as CAs (the extension BasicContraints will be present and cA will be set True)
#
# Intermediate Authority (a.k.a. Intermediate CA):
# Imprecise term occasionally used to define an entity which creates an
# intermediate certificate and could thus encompass an RA or a subordinate CA.
#
# Cross certificates (a.k.a. Chain or Bridge certificate):
# A cross-certificate is one in which the subject and the issuer are not the
# same but in both cases they are CAs (BasicConstraints extension is present and has cA set True).
#
# Intermediate certificates (a.k.a. Chain certificates):
# Imprecise term applied to any certificate which is not signed by a root CA.
# The term chain in this context is meaningless (but sounds complicated and
# expensive) and simply indicates that the certificate forms part of a chain.
#
# Qualified certificates: Defined in RFC 3739
# the term Qualified certificates relates to personal certificates (rather than
# server certificates) and references the European Directive on Electronic Signature (1999/93/EC)
# see check02102() above
#
# Multi-host certificates (aka wildcard certificates)
#
# EV Certificates (a.k.a. Extended Certificates): Extended Validation (EV)
# certificates are distinguished by the presence of the CertificatePolicies
# extension containg a registered OID in the policyIdentifier field. 
# see checkev() above
#
#

# RFC 3280
#  4.2.1.10  Basic Constraints
#    X509v3 Basic Constraints:
#        cA:FALSE
#        pathLenConstraint  INTEGER (0..MAX) OPTIONAL }
# RFC 4158

} # checkroot

sub checkprot($$) {
    #? check anything related to SSL protocol versions
    my ($host, $port) = @_;
    my $ssl;
    _y_CMD("checkprot() " . $cfg{'done'}->{'checkprot'});
    $cfg{'done'}->{'checkprot'}++;
    return if ($cfg{'done'}->{'checkprot'} > 1);
    # check SSL version support
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
        $checks{'hassslv2'}->{val}  = _subst($text{'disabled'}, "--no-SSLv2");
    } else {
        if ($prot{'SSLv2'}->{'cnt'} > 0) {
            $checks{'hassslv2'}->{val}  = " " if ($cfg{'nullssl2'} == 1);   # SSLv2 enabled, but no ciphers
        }
    }
    if ($cfg{'SSLv3'} == 0) {
        $checks{'hassslv3'}->{val}  = _subst($text{'disabled'}, "--no-SSLv3");
        $checks{'poodle'}  ->{val}  = _subst($text{'disabled'}, "--no-SSLv3");
    } else {    # SSLv3 enabled, check if there are ciphers
        if ($prot{'SSLv3'}->{'cnt'} > 0) {
            $checks{'hassslv3'}->{val}  = " ";  # POODLE if SSLv3 and ciphers
            $checks{'poodle'}  ->{val}  = "SSLv3";
        }
    }
} # checkprot

sub checkdest($$) {
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
    $checks{'reversehost'}->{val}   = $text{'no-dns'}   if ($cfg{'usedns'} <= 0);
    $checks{'ip'}->{val}            = $cfg{'IP'};

    # get selected cipher and store in %checks, also check for PFS
    $cipher = $data{'selected'}->{val}($host, $port);
    $ssl    = $data{'session_protocol'}->{val}($host, $port);
    $ssl    =~ s/[ ._-]//g;     # convert TLS1.1, TLS 1.1, TLS-1_1, etc. to TLS11
    my @prot = grep(/(^$ssl$)/i, @{$cfg{'versions'}});
    $checks{'selected'}->{val}      = $cipher;
    if ($#prot == 0) {          # found exactly one matching protocol
        $checks{'pfs_cipher'}->{val}= $cipher if ("" ne _ispfs($ssl, $cipher));
    } else {
        _warn("protocol '". join(';', @prot) . "' does not match; no selected protocol available");
    }

    # PFS is scary if the TLS session ticket is not random
    #  we should have different tickets in %data0 and %data
    #  it's ok if both are empty 'cause then no tickets are used
    $key   = 'session_ticket';
    $value = $data{$key}->{val}($host, $port);
    $checks{'session_random'}->{val} = $value if ($value eq $data0{$key}->{val});

    # check protocol support
    $key   = 'protocols';
    $value = $data{$key}->{val}($host, $port);
    $checks{'npn'}->{val}   = " " if ($value eq "");
    $key   = 'alpn';
    $value = $data{$key}->{val}($host, $port);
    $checks{'hasalpn'}->{val}   = " " if ($value eq "");
    $key   = 'no_alpn';
    $value = $data{$key}->{val}($host, $port);
    if ($value ne "") { # ALPN not negotiated
        # ALPN not negotiated
        if ($checks{'hasalpn'}->{val} eq "") {
            $checks{'hasalpn'}->{val}   = $value;
        } else {
            $checks{'hasalpn'}->{val}   = "<<mismatch: " . $checks{'hasalpn'}->{val} . " and '$value'>>";
        }
    }

    checkprot($host, $port);

    # vulnerabilities
    check_dh($host,$port); # Logjam vulnerability
    $checks{'crime'}->{val} = _iscrime($data{'compression'}->{val}($host));
    foreach $key (qw(resumption renegotiation)) {
        $value = $data{$key}->{val}($host);
        $checks{$key}->{val} = " " if ($value eq "");
    }
    #     Secure Renegotiation IS NOT supported
    $value = $data{'renegotiation'}->{val}($host);
    $checks{'renegotiation'}->{val} = $value if ($value =~ m/ IS NOT /i);
    $value = $data{'resumption'}->{val}($host);
    $checks{'resumption'}->{val}    = $value if ($value !~ m/^Reused/);

    # check target specials
    foreach $key (qw(krb5 psk_hint psk_identity srp session_ticket session_lifetime)) { # master_key session_id: see %check_dest above also
        $value = $data{$key}->{val}($host);
        $checks{$key}->{val} = " "    if ($value eq "");
        $checks{$key}->{val} = "None" if ($value =~ m/^\s*None\s*$/i);
        # if supported we have a value
        # TODO: see ZLIB also (seems to be wrong currently)
    }
    foreach $key (qw(heartbeat)) { # these are good if there is no value
        $checks{$key}->{val} = $data{$key}->{val}($host);
        $checks{$key}->{val} = ""     if ($checks{$key}->{val} =~ m/^\s*$/);
    }
    $checks{'heartbeat'}->{val} = $text{'no-tlsextdebug'} if ($cfg{'use_extdebug'} < 1);
} # checkdest

sub checkhttp($$) {
    #? HTTP(S) checks
    my ($host, $port) = @_;
    my $key = "";
    _y_CMD("checkhttp() " . $cfg{'done'}->{'checkhttp'});
    $cfg{'done'}->{'checkhttp'}++;
    return if ($cfg{'done'}->{'checkhttp'} > 1);

    # collect informations
    my $no = " "; # use a variable to make assignments below more human readable
    my $http_sts      = $data{'http_sts'}     ->{val}($host) || ""; # value may be undefined, avoid perl error
    my $http_location = $data{'http_location'}->{val}($host) || ""; #  "
    my $hsts_maxage   = $data{'hsts_maxage'}  ->{val}($host) || -1;
    my $hsts_fqdn     = $http_location;
       $hsts_fqdn     =~ s|^(?:https:)?//([^/]*)|$1|i; # get FQDN even without https:

    $checks{'hsts_is301'}->{val} = $data{'http_status'}->{val}($host) if ($data{'http_status'}->{val}($host) !~ /301/); # RFC6797 requirement
    $checks{'hsts_is30x'}->{val} = $data{'http_status'}->{val}($host) if ($data{'http_status'}->{val}($host) =~ /30[0235678]/); # not 301 or 304
    # perform checks
    $checks{'http_https'}->{val} = $no if ($http_location eq "");  # HTTP Location is there
    $checks{'hsts_redirect'}->{val} = $data{'https_sts'}->{val}($host) if ($http_sts ne ""); 
    if ($data{'https_sts'}->{val}($host) ne "") {
        $checks{'hsts_location'}->{val} = $data{'https_location'}->{val}($host) if ($data{'https_location'}->{val}($host) ne "");
        $checks{'hsts_refresh'} ->{val} = $data{'https_refresh'} ->{val}($host) if ($data{'https_refresh'} ->{val}($host) ne "");
        $checks{'hsts_ip'}      ->{val} = $host        if ($host =~ m/\d+\.\d+\.\d+\.\d+/); # RFC6797 requirement
        $checks{'hsts_fqdn'}    ->{val} = $hsts_fqdn   if ($http_location !~ m|^https://$host|i);
        $checks{'hsts_sts'}     ->{val} = $no          if ($data{'https_sts'}  ->{val}($host) eq "");
        $checks{'sts_subdom'}   ->{val} = $no          if ($data{'hsts_subdom'}->{val}($host) eq "");
        $checks{'sts_maxage'}   ->{val} = $hsts_maxage if (($hsts_maxage > $checks{'sts_maxage1m'}->{val}) or ($hsts_maxage < 1));
        $checks{'sts_maxage'}   ->{val}.= " = " . int($hsts_maxage / $checks{'sts_maxage1d'}->{val}) . " days" if ($checks{'sts_maxage'}->{val} ne ""); # pretty print
        $checks{'sts_maxagexy'} ->{val} = ($hsts_maxage > $checks{'sts_maxagexy'}->{val}) ? "" : "< ".$checks{'sts_maxagexy'}->{val};
        # other sts_maxage* are done below as they change {val}
    } else {
        $checks{'sts_maxagexy'} ->{val} = $text{'no-STS'};
        foreach $key (qw(hsts_location hsts_refresh hsts_fqdn hsts_sts sts_subdom sts_maxage)) {
            $checks{$key}->{val}    = $text{'no-STS'};
        }
    }
# TODO: invalid certs are not allowed for HSTS
    $checks{'hsts_fqdn'}->{val} = "<<N/A>>" if ($http_location eq "");   # useless if no redirect
    $checks{'pkp_pins'} ->{val} = $no if ($data{'https_pins'}->{val}($host) eq "");
# TODO: pins= ==> fingerprint des Zertifikats

    $no = $text{'no-STS'};
    $no = $text{'no-http'} if ($cfg{'usehttp'} < 1);
    # NOTE: following sequence is important!
    foreach $key (qw(sts_maxage1y sts_maxage1m sts_maxage1d sts_maxage0d)) {
        if ($data{'https_sts'}->{val}($host) ne "") {
            $checks{'sts_maxage'}->{score} = $checks{$key}->{score} if ($hsts_maxage < $checks{$key}->{val});
            $checks{$key}->{val}    = ($hsts_maxage < $checks{$key}->{val}) ? "" : "> ".$checks{$key}->{val};
        } else {
            $checks{$key}->{val}    = $no;
            $checks{$key}->{score}  = 0;
        }
    }
} # checkhttp

sub checkssl($$)  {
    #? SSL checks
    my ($host, $port) = @_;
    my $ciphers = shift;
    my $key;
    _y_CMD("checkssl() "  . $cfg{'done'}->{'checkssl'});
    $cfg{'done'}->{'checkssl'}++;
    return if ($cfg{'done'}->{'checkssl'} > 1);

    $cfg{'no_cert_txt'} = $text{'no-cert'} if ($cfg{'no_cert_txt'} eq ""); # avoid "yes" results
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
        $cfg{'done'}->{'checkdv'}++;   # "
        $cfg{'done'}->{'checkev'}++;   # "
        foreach $key (sort keys %checks) { # anything related to certs need special setting
            $checks{$key}->{val} = $cfg{'no_cert_txt'} if (_is_member($key, \@{$cfg{'check_cert'}}));
        }
        $checks{'hostname'}     ->{val} = $cfg{'no_cert_txt'};
        $checks{'bsi-tr-02102+'}->{val} = $cfg{'no_cert_txt'};
        $checks{'bsi-tr-02102-'}->{val} = $cfg{'no_cert_txt'};
        $checks{'bsi-tr-03116+'}->{val} = $cfg{'no_cert_txt'};
        $checks{'bsi-tr-03116-'}->{val} = $cfg{'no_cert_txt'};
        $checks{'rfc6125_names'}->{val} = $cfg{'no_cert_txt'};
    }

    if ($cfg{'usehttp'} == 1) {
        checkhttp( $host, $port);
    } else {
        $cfg{'done'}->{'checkhttp'}++;
        foreach $key (sort keys %checks) {
            $checks{$key}->{val} = $text{'no-http'} if (_is_member($key, \@{$cfg{'cmd-http'}}));
        }
    }
    # some checks accoring ciphers and compliance are done in checkciphers()
    # and check02102(); some more are done in checkhttp()
    # now do remaining for %checks
    checkdest( $host, $port);
    my $txt = $checks{'hsts_sts'}->{val};
    $checks{'rfc7525'}->{val} .= _subst($text{'missing'}, 'STS') if ($txt ne "");

# TODO: folgende Checks implementieren
    foreach $key (qw(verify_hostname verify_altname verify dates fingerprint)) {
# TODO: nicht sinnvoll wenn $cfg{'no_cert'} > 0
    }

} # checkssl

sub scoring($$) {
    #? compute scoring of all checks; sets values in %scores
    my ($host, $port) = @_;
    my ($key, $value);

    # http
    #  some scores are set in checkhttp()
    my $http_location = $data{'http_location'}->{val}($host) || "";
    $scores{'check_http'}->{val}    = 100;
    $checks{'hsts_fqdn'}->{score}   = 0 if ($http_location eq "");

    foreach $key (sort keys %checks) {
        next if ($key =~ m/^(ip|reversehost)/); # not scored
        next if ($key =~ m/^(sts_)/);           # needs special handlicg
        next if ($key =~ m/^(closure|fallback|cps|krb5|lzo|open_pgp|order|pkp_pins|psk_|rootcert|srp|zlib)/); # FIXME: not yet scored
        next if ($key =~ m/^TLSv1[123]/); # FIXME:
        $value = $checks{$key}->{val};
        # TODO: go through @results
# TODO   foreach $sec (qw(LOW WEAK MEDIUM HIGH -?-)) {
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
} # scoring

## definitions: print functions
## -------------------------------------

sub _dump($$) {
    my ($label, $value) = @_;
        $label =~ s/\n//g;
        $label = sprintf("%s %s", $label, '_' x (75 -length($label)));
    $value = "" if (!defined $value); # value parameter is optional
    printf("#{ %s\n\t%s\n#}\n", $label, $value);
    # using curly brackets 'cause they most likely are not part of any data
} # _dump
sub printdump($$$)  {
    #? just dumps internal database %data and %check_*
    my ($legacy, $host, $port) = @_;   # NOT IMPLEMENTED
    my $key;
    print '######################################################################### %data';
    foreach $key (keys %data) {
        next if (_is_intern($key) > 0);  # ignore aliases
        _dump($data{$key}->{txt}, $data{$key}->{val}($host));
    }
    print '######################################################################## %check';
    foreach $key (keys %checks) { _dump($checks{$key}->{txt}, $checks{$key}->{val}); }
} # printdump

sub printruler()    { print "=" . '-'x38, "+" . '-'x35 if ($cfg{'out_header'} > 0); }

sub printheader($$) {
    #? print title line and table haeder line if second argument given
    my ($txt, $desc, $rest) = @_;
    return if ($cfg{'out_header'} <= 0);
    print $txt;
    return if ($desc =~ m/^ *$/); # title only if no more arguments
    printf("= %-37s %s\n", $text{'desc'}, $desc);
    printruler();
} # printheader

sub printfooter($)  {
    #? print footer line according given legacy format
    my $legacy  = shift;
    if ($legacy eq 'sslyze')    { print "\n\n SCAN COMPLETED IN ...\n"; }
    # all others are empty, no need to do anything
} # printfooter

sub printtitle($$$$) {
    #? print title according given legacy format
    my ($legacy, $ssl, $host, $port) = @_;
    my $txt     = _subst($text{'out-ciphers'}, $ssl);
    local    $\ = "\n";
    if ($legacy eq 'sslyze')    {
        my $txt = " SCAN RESULTS FOR " . $host . " - " . $cfg{'IP'};
        print "$txt";
        print " " . "-" x length($txt);
    }
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
    if ($legacy eq 'compact')   { print "Checking $ssl Ciphers ..."; }
    if ($legacy eq 'quick')     { printheader($txt, ""); }
    if ($legacy eq 'simple')    { printheader($txt, ""); }
    if ($legacy eq 'full')      { printheader($txt, ""); }
} # printtitle

sub print_line($$$$$$)  {
    #? print label and value separated by separator
    #? print hostname and key depending on --showhost and --trace-key option
    my ($legacy, $host, $port, $key, $text, $value) = @_;
        $text   = STR_NOTXT if (! defined $text);   # defensive programming: ..
        $value  = STR_UNDEF if (! defined $value);  # .. missing variable declaration
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
} # print_line

sub print_data($$$$)    {
    # print given label and text from %data according given legacy format
    my ($legacy, $host, $port, $key) = @_;
    if (_is_hashkey($key, \%data) < 1) {    # silently ignore unknown labels
        _warn("unknown label '$key'; output ignored"); # seems to be a programming error
        return;
    }
    my $label = ($data{$key}->{txt} || ""); # defensive programming
    my $value =  $data{$key}->{val}($host, $port) || "";
    # { always pretty print
        if ($key =~ m/X509$/) {
            $key =~ s/X509$//;
            $value =~ s#/([^=]*)#\n   ($1)#g;
            $value =~ s#=#\t#g;
            print_line($legacy, $host, $port, $key, $data{$key}->{txt}, $value);
            return;
        }
    # }
    if ((1 eq _is_hexdata($key)) && ($value !~ m/^\s*$/)) {
        # check for empty $value to avoid warnings with -w
        # pubkey_value may look like:
        #   Subject Public Key Info:Public Key Algorithm: rsaEncryptionPublic-Key: (2048 bit)Modulus=00c11b:...
        # where we want to convert the key value only but not its prefix
        # hence the final : is converted to =
        # (seems to happen on Windows only; reason yet unknown)
        $value =~ s/([Mm]odulus):/$1=/; #
        my ($k, $v) = split("=", $value);
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
        return;
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
} # print_data

sub print_check($$$$$)  {
    #? print label and result of check
    my ($legacy, $host, $port, $key, $value) = @_;
    $value = $checks{$key}->{val} if (!defined $value); # defensive programming
    my $label = $checks{$key}->{txt} if ($legacy ne 'key');
    print_line($legacy, $host, $port, $key, $label, $value);
} # print_check

sub print_size($$$$)    {
    #? print label and result for length, count, size, ...
    my ($legacy, $host, $port, $key) = @_;
    my $value = "";
    $value = " bytes" if ($key =~ /^(len)/);
    $value = " bits"  if ($key =~ /^len_(modulus|publickey|sigdump)/);
    print_check($legacy, $host, $port, $key, $checks{$key}->{val} . $value);
} # print_size

sub print_cipherruler_dh{ print "=   " . "-"x35 . "+-------------------------" if ($cfg{'out_header'} > 0); }
sub print_cipherruler   { print "=   " . "-"x35 . "+-------+-------" if ($cfg{'out_header'} > 0); }
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
    if ($legacy eq 'cipher-dh') { printf("=   %-34s\t%s\n", $text{'cipher'}, $text{'dh-param'});
                                  print_cipherruler_dh(); }
    if ($legacy eq 'full')      {
        # host:port protocol    supported   cipher    compliant security    description
        printf("= %s\t%s\t%s\t%s\t%s\t%s\t%s\n", 'host:port', 'Prot.', 'supp.', $text{'cipher'}, 'compliant', $text{'security'}, $text{'desc'});
    }
    # all others are empty, no need to do anything
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
        printf("    %s  %s  %s  %s\n", $yesno, $ssl, $bit, $cipher);
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
} # print_cipherline

sub print_cipherdefault($$$$) {
    #? print default cipher according given legacy format
    my ($legacy, $ssl, $host, $port) = @_;
    my $yesno   = 'yes';
    if ($legacy eq 'sslyze')    { print "\n\n      Preferred Cipher Suites:"; }
    if ($legacy eq 'sslaudit')  {} # TODO: cipher name should be DEFAULT
    if ($legacy eq 'sslscan')   { print "\n  Preferred Server Cipher(s):"; $yesno = "";}
    # all others are empty, no need to do anything
    print_cipherline($legacy, $ssl, $host, $port, $data{'selected'}->{val}($host), $yesno);
} # print_cipherdefault

sub print_ciphertotals($$$$) {
    #? print total number of ciphers supported for SSL version according given legacy format
    my ($legacy, $ssl, $host, $port) = @_;
    my ($key, $sec);
    if ($legacy eq 'ssldiagnos') {
        print "\n-= SUMMARY =-\n";
        printf("Weak:         %s\n", $prot{$ssl}->{'WEAK'});
        printf("Intermediate: %s\n", $prot{$ssl}->{'MEDIUM'}); # MEDIUM
        printf("Strong:       %s\n", $prot{$ssl}->{'HIGH'});   # HIGH
    }
    if ($legacy =~ /(full|compact|simple|quick)/) {
        printheader(_subst($text{'out-summary'}, $ssl), "");
        _trace_cmd('%checks');
        foreach $key (qw(LOW WEAK MEDIUM HIGH -?-)) {
            print_line($legacy, $host, $port, "$ssl-$key", $prot_txt{$key}, $prot{$ssl}->{$key});
            # NOTE: "$ssl-$key" does not exist in %checks or %prot
        }
    }
} # print_ciphertotals

sub _is_print($$$) {
    #? return 1 if parameter indicate printing
    my $enabled = shift;
    my $print_disabled = shift;
    my $print_enabled  = shift;
    return 1 if ($print_disabled == $print_enabled);
    return 1 if ($print_disabled && ($enabled eq 'no' ));
    return 1 if ($print_enabled  && ($enabled eq 'yes'));
    return 0;
} # _is_print

sub _print_results($$$@) {
    #? print all ciphers from @results if match $ssl and $yesno
    my $ssl     = shift;
    my $host    = shift;
    my $port    = shift;
    my $yesno   = shift; # only print these results, all if empty
    my @results = @_;
    my $print   = 0; # default: do not print
    my $c       = "";
    local    $\ = "\n";
    foreach $c (@results) {
        next if  (${$c}[0] ne $ssl);
        next if ((${$c}[2] ne $yesno) and ($yesno ne ""));
        $print = _is_print(${$c}[2], $cfg{'disabled'}, $cfg{'enabled'});
        print_cipherline($cfg{'legacy'}, $ssl, $host, $port, ${$c}[1], ${$c}[2]) if ($print ==1);
    }
} # _print_results

sub printciphercheck($$$$$@)    {
    #? print all cipher check results according given legacy format
    my $legacy  = shift;
    my $ssl     = shift;
    my $host    = shift;
    my $port    = shift;
    my $count   = shift; # print title line if 0
    my @results = @_;
    local    $\ = "\n";
    print_cipherhead( $legacy) if ($count == 0);
    print_cipherdefault($legacy, $ssl, $host, $port) if ($legacy eq 'sslaudit');

    if ($legacy ne 'sslyze') {
        _print_results($ssl, $host, $port, "", @results);
        print_cipherruler() if ($legacy eq 'simple');
    } else {
        print "\n  * $ssl Cipher Suites :";
        print_cipherdefault($legacy, $ssl, $host, $port);
        if (($cfg{'enabled'} == 1) or ($cfg{'disabled'} == $cfg{'enabled'})) {
            print "\n      Accepted Cipher Suites:";
            _print_results($ssl, $host, $port, "yes", @results);
        }
        if (($cfg{'disabled'} == 1) or ($cfg{'disabled'} == $cfg{'enabled'})) {
            print "\n      Rejected Cipher Suites:";
            _print_results($ssl, $host, $port, "no", @results);
        }
    }
    #print_ciphertotals($legacy, $ssl, $host, $port);  # up to version 15.10.15
    print_check($legacy, $host, $port, 'cnt_totals', $#results) if ($cfg{'verbose'} > 0);
    printfooter($legacy);
} # printciphercheck

sub printciphers_dh($$$) {
    #? print ciphers and DH parameter from target
    # currently DH parameters are available with openssl only
    my ($legacy, $host, $port) = @_;
    my $ssl;
    my $openssl_version = get_openssl_version($cmd{'openssl'});
    _trace1("printciphers_dh: openssl_version: $openssl_version");
    if ($openssl_version lt "1.0.2") { # yes perl can do this check
        _warn("ancient openssl $openssl_version: using '-msg' option to get DH parameters");
        $cfg{'openssl_msg'} = '-msg' if ($cfg{'openssl_msg'} eq "");
        require Net::SSLhello; # to parse output of '-msg'; ok here, as perl handles multiple includes proper
    }
    foreach $ssl (@{$cfg{'version'}}) {
        printtitle($legacy, $ssl, $host, $port);
        print_cipherhead( 'cipher-dh');
        foreach my $c (@{$cfg{'ciphers'}}) {
            #next if ($c !~ /$cfg{'regex'}->{'EC'}/);
            my ($supported, $dh) = _useopenssl($ssl, $host, $port, $c);
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
} # printciphers_dh

sub printprotocols($$$) {
    #? print table with cipher informations per protocol
    # number of found ciphers, various risks ciphers, default and PFS cipher
    # prints information stored in %prot
    my ($legacy, $host, $port) = @_;
    local $\ = "\n";
    my $ssl;
    if ($cfg{'out_header'}>0) {
        printf("# H=HIGH  M=MEDIUM  L=LOW  W=WEAK  tot=total amount  PFS=selected cipher with PFS\n") if ($verbose > 0);
        printf("%s\t%3s %3s %3s %3s %3s %3s %-31s %s\n", "=", qw(H M L W PFS tot default PFS));
        printf("=------%s%s\n", ('+---' x 6), '+-------------------------------+---------------');
    }
    #   'PROT-LOW'      => {'txt' => "Supported ciphers with security LOW"},
    foreach $ssl (@{$cfg{'versions'}}) {
        # $cfg{'versions'} is sorted in contrast to "keys %prot" 
        next if (($cfg{$ssl} == 0) and ($verbose <= 0));  # NOT YET implemented with verbose only
        my $key = $ssl . $text{'separator'};
           $key = sprintf("[0x%x]", $prot{$ssl}->{hex}) if ($legacy eq 'key');
        print_line('_cipher', $host, $port, $ssl, $ssl, ""); # just host:port:#[key]:
        printf("%-7s\t%3s %3s %3s %3s %3s %3s %-31s %s\n", $key,
                $prot{$ssl}->{'HIGH'}, $prot{$ssl}->{'MEDIUM'},
                $prot{$ssl}->{'LOW'},  $prot{$ssl}->{'WEAK'},
                ($#{$prot{$ssl}->{'pfs_ciphers'}} + 1), $prot{$ssl}->{'cnt'},
                $prot{$ssl}->{'default'}, $prot{$ssl}->{'pfs_cipher'}
        );
    }
    if ($cfg{'out_header'}>0) {
        printf("=------%s%s\n", ('+---' x 6), '+-------------------------------+---------------');
    }
} # printprotocols

sub printdata($$$) {
    #? print information stored in %data
    my ($legacy, $host, $port) = @_;
    my $key  = "";
    local $\ = "\n";
    printheader($text{'out-infos'}, $text{'desc-info'});
    _trace_cmd('%data');
    foreach $key (@{$cfg{'do'}}) {
        next if (_is_member( $key, \@{$cfg{'cmd-NOT_YET'}}) > 0);
        next if (_is_member( $key, \@{$cfg{'ignore-out'}})  > 0);
        next if (_is_hashkey($key, \%data) < 1);
        if ($cfg{'experimental'} == 0) {
            next if (_is_member( $key, \@{$cfg{'cmd-experiment'}}) > 0);
        }
        # special handling vor +info--v
        if (_is_do('info--v') > 0) {
            next if ($key eq 'info--v');
            next if ($key =~ m/$cfg{'regex'}->{'cmd-intern'}/i);
        } else {
            next if (_is_intern( $key) > 0);
        }
        _y_CMD("(%data)   +" . $key);
        if (_is_member( $key, \@{$cfg{'cmd-NL'}}) > 0) {
            # for +info print multine data only if --v given
            # if command given explizitely, i.e. +text, print
            next if ((_is_do('info') > 0) and ($cfg{'verbose'} <= 0));
        }
        if ($cfg{'format'} eq "raw") {  # should be the only place where format=raw counts
            print $data{$key}->{val}($host);;
        } else {
            print_data($legacy, $host, $port, $key);
        }
    }
} # printdata

sub printchecks($$$) {
    #? print results stored in %checks
    my ($legacy, $host, $port) = @_;
    my $key  = "";
    local $\ = "\n";
    printheader($text{'out-checks'}, $text{'desc-check'});
    _trace_cmd(' printchecks: %checks');
    if (_is_do('selected')) {           # value is special
        $key = $checks{'selected'}->{val};
        print_line($legacy, $host, $port, 'selected', $checks{'selected'}->{txt}, "$key " . get_cipher_sec($key));
    }
    _warn("can't print certificate sizes without a certificate (--no-cert)") if ($cfg{'no_cert'} > 0);
    foreach $key (@{$cfg{'do'}}) {
        _trace("printchecks: (%checks) ?" . $key);
        next if (_is_member( $key, \@{$cfg{'cmd-NOT_YET'}}) > 0);
        next if (_is_member( $key, \@{$cfg{'ignore-out'}})  > 0);
        next if (_is_hashkey($key, \%checks) < 1);
        next if (_is_intern( $key) > 0);# ignore aliases
        next if ($key =~ m/$cfg{'regex'}->{'SSLprot'}/); # these counters are already printed
        next if ($key eq 'selected');   # done above
        if ($cfg{'experimental'} == 0) {
            next if (_is_member( $key, \@{$cfg{'cmd-experiment'}}) > 0);
        }
        _y_CMD("(%checks) +" . $key);
        if ($key =~ /$cfg{'regex'}->{'cmd-sizes'}/) { # sizes are special
            print_size($legacy, $host, $port, $key) if ($cfg{'no_cert'} <= 0);
        } else {
            print_check($legacy, $host, $port, $key, _setvalue($checks{$key}->{val}));
        }
    }
} # printchecks

## definitions: print functions for help and information
## -------------------------------------

sub printquit() {
    #? print internal data
    # call this function with:
    #    $0 `\
    #      gawk '/--(help|trace-sub)/{next}/--h$/{next}/\+traceSUB/{next}($2~/^-/){$1="";print}' o-saft-man.pm\
    #      |tr ' ' '\012' \
    #      |sort -u \
    #      |egrep '^(--|\+)' \
    #      |egrep -v '^--[v-]-' \
    #      |egrep -v '--user-*' \
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
        #_warn(" +quit  command usefull with --v and/or --trace* option only");
        _warn(" +quit  command should be used with  --trace=arg  option");
    }
    _v_print("\n# some information may appear multiple times\n#");
    $cfg{'verbose'} = 2;
    $cfg{'trace'}   = 2;
    $cfg{'traceARG'}= 1; # for _yeast_args()
    _yeast_init();
    # _yeast_args();  # duplicate call, see in main at "set environment"
    print "# TEST done.";
} # printquit

sub printversionmismatch() {
    #? check if openssl and compiled SSLeay are of same version
    my $o = Net::SSLeay::OPENSSL_VERSION_NUMBER();
    my $s = Net::SSLeay::SSLeay();
    if ($o ne $s) {
        _warn("used openssl version '$o' differs from compiled Net:SSLeay '$s'; ignored");
    }
} # printversionmismatch

sub printversion() {
    #? print program and module versions
    local $\ = "\n";
    print '# Path = ' . $mepath if ($cfg{'verbose'} > 1);
    print '# @INC = ' . join(" ", @INC) . "\n" if ($cfg{'verbose'} > 0);
    print "=== $0 $VERSION ===";
    print "    Net::SSLeay::"; # next two should be identical; 0x1000000f => openssl-1.0.0
    print "       ::OPENSSL_VERSION_NUMBER()    0x" . Net::SSLeay::OPENSSL_VERSION_NUMBER();
    print "       ::SSLeay()                    0x" . Net::SSLeay::SSLeay();
    if ($cfg{'verbose'} > 0) {
        # TODO: not all versions of Net::SSLeay have constants like 
        # Net::SSLeay::SSLEAY_CFLAGS, hence we use hardcoded integers
        print "       ::SSLEAY_DIR                  " . Net::SSLeay::SSLeay_version(5);
        print "       ::SSLEAY_BUILD_ON             " . Net::SSLeay::SSLeay_version(3);
        print "       ::SSLEAY_PLATFORM             " . Net::SSLeay::SSLeay_version(4);
        print "       ::SSLEAY_CFLAGS               " . Net::SSLeay::SSLeay_version(2);
    }
    print "    Net::SSLeay::SSLeay_version()    " . Net::SSLeay::SSLeay_version(); # no parameter is same as parameter 0

    print "= openssl =";
    print "    version of external executable   " . Net::SSLinfo::do_openssl('version', "", "", "");
    my $openssl = $cmd{'openssl'};
    foreach my $p ("", split(":", $ENV{'PATH'})) { # try to find path
        # "" above ensures that full path in $cmd{'openssl'} will be checked
        $openssl = "$p/$cmd{'openssl'}";
        last if (-e $openssl);
        $openssl = "<<$cmd{'openssl'} not found>>";
    }
    $openssl =~ s#//#/#g;       # make a nice path (see first path "" above)
    print "    external executable              " . $openssl;
        #  . ($cmd{'openssl'} eq $openssl)?" (executable not found??)":"";
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
    my @ciphers= Net::SSLinfo::cipher_local();  # openssl ciphers ALL:aNULL:eNULL
    print "    number of supported ciphers      " . @ciphers;
    print "    list of supported ciphers        " . join(" ", @ciphers) if ($cfg{'verbose'} > 0);
    print "    openssl supported SSL versions   " . join(" ", @{$cfg{'version'}});
    print "    $me known SSL versions     "       . join(" ", @{$cfg{'versions'}});
    printversionmismatch();

    print "= $me +cipherall =";
    # TODO: would be nicer:   $cfg{'cipherranges'}->{'rfc'} =~ s/\n//g;
    print "    default list of ciphers          " . $cfg{'cipherranges'}->{'rfc'};
    if ($cfg{'verbose'} > 0) {
	# these lists are for special purpose, so with --v only
        print "    long list of ciphers         " . $cfg{'cipherranges'}->{'long'};
        print "    huge list of ciphers         " . $cfg{'cipherranges'}->{'huge'};
        print "    safe list of ciphers         " . $cfg{'cipherranges'}->{'safe'};
        print "    full list of ciphers         " . $cfg{'cipherranges'}->{'full'};
        print "    SSLv2 list of ciphers        " . $cfg{'cipherranges'}->{'SSLv2'};
        print "    SSLv2_long list of ciphers   " . $cfg{'cipherranges'}->{'SSLv2_long'};
        print "    shifted list of ciphers      " . $cfg{'cipherranges'}->{'shifted'};
    }

# TODO: i.g. OPENSSL_VERSION_NUMBER() returns same value as SSLeay()
#       but when using libraries with LD_LIBRARY_PATH or alike, these
#       versions differ

    # get a quick overview also
    print "= Required (and used) Modules =";
    print '    @INC                 ', "@INC";
    my ($m, $d, $v, %p);
    printf("=   %-22s %-9s%s\n", "module name", "VERSION", "found in");
    printf("=   %s+%s+%s\n",     "-"x22,        "-"x8,     "-"x42);
    foreach $m (qw(IO::Socket::INET IO::Socket::SSL Net::DNS Net::SSLeay Net::SSLinfo Net::SSLhello)) {
        no strict 'refs';   # avoid: Can't use string ("Net::DNS") as a HASH ref while "strict refs" in use
        # we expect ::VERSION in all these modules
        ($d = $m) =~ s#::#/#g;  $d .= '.pm';   # convert string to key for %INC
        $v  = $m . "::VERSION";
        printf("    %-22s %-9s%s\n", $m, $$v, $INC{$d});
    }
    if ($cfg{'verbose'} > 0) {
        print "\n= Loaded Modules =";
        foreach $m (sort keys %INC) {
            printf("    %-22s %6s\n", $m, $INC{$m});
            $d = $INC{$m}; $d =~ s#$m$##; $p{$d} = 1;
        }
        print "\n= Loaded Module Versions =";
        no strict 'refs';   # avoid: Can't use string ("AutoLoader::") as a HASH ref while "strict refs" in use
        foreach $m (sort keys %main:: ) {
            next if $m !~ /::/;
            $d = "?";       # beat the "Use of uninitialized value" dragon
            $d = ${$$m{'VERSION'}} if (defined ${$$m{'VERSION'}});
            printf("    %-22s %6s\n", $m, $d);
        }
    }
    return if ($^O =~ m/MSWin32/); # not Windows
    if ($cfg{'verbose'} > 1) {
        print "\n= Used Shared Objects =";
        # quick&dirty, don't want to use ::Find module
        foreach $d (sort keys %p) {
             next if ($d =~ m/^\s*$/);
             print "# find $d -name SSLeay.so\\* -o -name libssl.so\\* -o -name libcrypto.so\\*";
             print qx(find $d -name SSLeay.so\\* -o -name libssl.so\\* -o -name libcrypto.so\\*);
        }
    }
} # printversion

sub printopenssl() {
    #? print openssl version
    print Net::SSLinfo::do_openssl('version', "", "", "");
    printversionmismatch();
} # printopenssl

sub _hex_like_openssl($) {
    # convert full hex constant to format used by openssl's output
    my $c = shift;
    $c =~ s/0x(..)(..)(..)(..)/0x$2,0x$3,0x$4 - /; # 0x0300C029 ==> 0x00,0xC0,0x29
    $c =~ s/^0x00,// if ($c ne "0x00,0x00,0x00");  # first byte omitted if 0x00
    return sprintf("%22s", $c);
} # _hex_like_openssl

sub printciphers() {
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
    my $c = "";
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
       $ciphers     = Net::SSLinfo::cipher_local() if ($cfg{'verbose'} > 0);

    printheader(_subst($text{'out-list'}, $0), "");
    # all following headers printed directly instead of using printheader()

    if ($cfg{'legacy'} eq "ssltest") {        # output looks like: ssltest --list
        _warn("not all ciphers listed");
        foreach $ssl (qw(SSLv2 SSLv3 TLSv1)) {# SSLv3 and TLSv1 are the same, hence search both
          print "SSLv2 Ciphers Supported..."       if ($ssl eq 'SSLv2');
          print "SSLv3/TLSv1 Ciphers Supported..." if ($ssl eq 'SSLv3');
          foreach $c (sort keys %ciphers) {
            next if ($ssl ne get_cipher_ssl($c));
            # FIXME: sprintf below gives warning if $bits == 0
            $bit =  get_cipher_bits($c); $bit =  sprintf("%03d", $bit) if ($bit ne '-?-');
            $aut =  get_cipher_auth($c); $aut =  "No" if ($aut =~ /none/i);
            $key =  get_cipher_keyx($c); $key =~ s/[()]//g;
            $mac =  get_cipher_mac($c);
            $enc =  get_cipher_enc($c);
            printf("   %s, %s %s bits, %s Auth, %s MAC, %s Kx\n",
                $c, $enc, $bit, $aut, $mac, $key,
            );
          }
        }
    }

    if ($cfg{'legacy'} eq "openssl") {        # output looks like: openssl ciphers -[v|V]
        foreach $c (sort keys %ciphers) {
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
        foreach $c (sort keys %ciphers) {
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
        foreach $c (sort keys %ciphers) {
            my $can = " "; # FIXME
            if ($cfg{'verbose'} > 0) {
                if (0 >= grep({$_ eq $c} split(":", $ciphers))) {
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
            foreach $c (split(':', $ciphers)) {
                next if ($c eq $dupl);
                push(@test, $c) if (  defined $ciphers{$c});
                push(@miss, $c) if (! defined $ciphers{$c});
                $dupl = $c;
            }
            # no customizable texts from %text, as it's for --v only
            print "\n# Ciphers marked with # above are not supported by local SSL implementation.\n";
            print "Supported Ciphers:        ",  $have_cipher;
            print "Unsupported Ciphers:      ",  $miss_cipher;
            print "Testable Ciphers:         ",  scalar(@test);
            print "Ciphers missing in $mename:", scalar(@miss), "  ", join(" ", @miss) if (scalar(@miss) > 0);
            print "Ciphers in alias list:    ",  scalar(keys %cipher_alias); # FIXME: need to count values
        }
    }

} # printciphers

sub printusage_exit($) {
    local $\ = "\n";
    print STR_USAGE, @_;
    print "# most common usage:
  $me +info   your.tld
  $me +check  your.tld
  $me +cipher your.tld
# for more help use:
  $me --help
    ";
    exit 2;
} # printusage_exit

# end sub

usr_pre_args();

## scan options and arguments
## -------------------------------------
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
    _y_ARG($arg);
    push(@dbxarg, $arg) if (($arg !~ m/^--cfg[_-]/) && (($arg =~ m/^[+-]/) || ($typ ne "HOST")));
    push(@dbxcfg, $arg) if  ($arg =~ m/^--cfg[_-]/);    # both aprox. match are sufficient for debugging

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
    # $typ='HOST' is handles at end of loop, as it may appear anywhere in the
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
        _y_ARG("argument? $arg, typ= $typ");
        push(@dbxexe, join("=", $typ, $arg)) if ($typ =~ m/OPENSSL|ENV|EXE|LIB/);
        #  $typ = '????'; # expected next argument
        #  +---------+----------+------------------------------+--------------------
        #   argument to process   what to do                    expect next argument
        #  +---------+----------+------------------------------+--------------------
        if ($typ =~ m/^CFG/)    { _cfg_set($typ, lc($arg));     $typ = 'HOST'; }
           # lc($arg) is contribution to old keys (pre 14.10.13) where keys in
           # our internal hashes %check etc. where case sensitive
           # we don't want to force users to rewrite their existing .o-saft.pl
           # hence we simply convert anything to lower case
        if ($typ eq 'ENV')      { $cmd{'envlibvar'} = $arg;     $typ = 'HOST'; }
        if ($typ eq 'OPENSSL')  { $cmd{'openssl'}   = $arg;     $typ = 'HOST'; }
        if ($typ eq 'SSLCNF')   { $cfg{'openssl_cnf'}   = $arg; $typ = 'HOST'; }
        if ($typ eq 'SSLFIPS')  { $cfg{'openssl_fips'}  = $arg; $typ = 'HOST'; }
        if ($typ eq 'NO_OUT')   { push(@{$cfg{'ignore-out'}}, $arg);$typ = 'HOST'; }
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
        if ($typ eq 'SSLRETRY') { $cfg{'sslhello'}->{'retry'}   = $arg;     $typ = 'HOST'; }
        if ($typ eq 'SSLTOUT')  { $cfg{'sslhello'}->{'timeout'} = $arg;     $typ = 'HOST'; }
        if ($typ eq 'MAXCIPHER'){ $cfg{'sslhello'}->{'maxciphers'}= $arg;   $typ = 'HOST'; }
        if ($typ eq 'STARTTLS') { $cfg{'starttls'}  = $arg;     $typ = 'HOST'; }
        if ($typ eq 'TLSDELAY') { $cfg{'starttlsDelay'} = $arg; $typ = 'HOST'; }
        if ($typ eq 'PORT')     { $cfg{'port'}      = $arg;     $typ = 'HOST'; }
        #if ($typ eq 'HOST')    # not done here, but at end of loop
            #  ------+----------+------------------------------+--------------------
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
            if (1 == grep(/^$arg$/i, @{$cfg{'legacys'}})) {
                $cfg{'legacy'} = lc($arg);
            } else {
                _warn("unknown legacy '$arg'; setting ignored") if ($arg !~ /^\s*$/);
            }
        }
        if ($typ eq 'FORMAT')   {
            $arg = 'esc' if ($arg =~ m#^[/\\]x$#);      # \x and /x are the same
            if (1 == grep(/^$arg$/, @{$cfg{'formats'}})) {
                $cfg{'format'} = $arg;
            } else {
                _warn("unknown format '$arg'; setting ignored") if ($arg !~ /^\s*$/);
            }
        }
        if ($typ eq 'CRANGE')    {
            if (1 == grep(/^$arg$/, keys %{$cfg{'cipherranges'}})) {
                $cfg{'cipherrange'} = $arg;
            } else {
                _warn("unknown cipher range '$arg'; setting ignored") if ($arg !~ /^\s*$/);
            }
        }
        _y_ARG("argument= $arg");
        #
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
            $cfg{'traceARG'}++   if ($arg =~ m#arg#i);
            $cfg{'traceCMD'}++   if ($arg =~ m#cmd#i);
            $cfg{'traceKEY'}++   if ($arg =~ m#key#i);
            $cfg{'traceTIME'}++  if ($arg =~ m#time#i);
            $cfg{'traceME'}++    if ($arg =~ m#^me(?:only)?#i);
            $cfg{'traceME'}--    if ($arg =~ m#^notme#i);
            $cfg{'trace'} = $arg if ($arg =~ m#\d+#i);
            # now magic starts ...
            next if ($arg =~ m#^(ARG|CMD|KEY|ME|TIME|\d+)$#i); # matched before
            # if we reach here, argument did not match valid value for --trace,
            # then simply increment trace level and process argument below
            # FIXME: should push back arg if not a number
            $cfg{'trace'}++;
        } # else $typ handled before if-condition
        $typ = 'HOST';          # expect host as next argument
        next;
    } # ne 'HOST' option arguments

    next if ($arg =~ /^\s*$/);# ignore empty arguments

    # remove trailing = for all options
    # such options are incorrectly used, or are passed in in CGI mode
    # NOTE: this means that we cannot have empty strings as value
    if ($arg =~ m/^-[^=]*=$/) {
        # in CGI mode all options are passed with a trailing  =  even those
        # which do not have an argument (value)
        # so we cannot ignore all options with empty value, like: --header=
        # following regex contains those options, which have a value,  only
        # these are ignored if the value is empty
        if ($arg =~ /^(?:[+]|--)(?:cmd|help|host|port|format|legacy|timeout|trace|openssl|(?:cipher|proxy|sep|starttls|exe|lib|ca-|cfg-|ssl-|usr-).*)/) {
            _warn("option with empty argument '$arg'; option ignored") if ($cgi == 0);
            next;
        }
        $arg =~ s/=+$//;
    }

    # first handle some old syntax for backward compatibility
    if ($arg =~ /^--cfg(cmd|score|text)-([^=]*)=(.*)/) {
        $typ = 'CFG-'.$1; unshift(@argv, $2 . "=" . $3);   # convert to new syntax
        _warn("old (pre 13.12.12) syntax '--cfg-$1-$2'; converted to '--cfg-$1=$2'; please consider changing your files");
        next; # no more normalisation!
    }
    if ($arg =~ /^--set[_-]?score=(.*)/) {
        _warn("old (pre 13.12.11) syntax '--set-score=*' obsolete, please use --cfg-score=*; option ignored");
        next;
    }

    # all options starting with  --usr or --user  are not handled herein
    # push them on $cfg{'usr-args'} so they can be accessd in o-saft-*.pm
    if ($arg =~ /^--use?r/) {
        $arg =~ s/^(?:--|\+)//;     # strip leading chars
        push(@{$cfg{'usr-args'}}, $arg);
        next;
    }

    # --h --help and --help=gen-* are already handled in BEGIN {}
    # other --help=* options are special as they require settings in %cfg
    if ($arg =~ /^(?:--|\+)(todo|help)=?(.*)?$/) {
        $arg = $1;
        if (defined $2) {
            $arg = $2 if ($2 !~ /^\s*$/);   # if it was --help=*
        }
        require "o-saft-man.pm";    # include if necessary only; dies if missing
        printhelp($arg);
        exit 0;
    }

    #{ handle some specials
    #!#--------+------------------------+--------------------------+------------
    #!#           argument to check       what to do             what to do next
    #!#--------+------------------------+--------------------------+------------
    if ($arg eq  '--trace--')           { $cfg{'traceARG'}++;       next; } # for backward compatibility
    if ($arg =~ /^--?starttls$/i)       { $cfg{'starttls'} ="SMTP"; next; } # shortcut for  --starttls=SMTP
    if ($arg =~ /^--cgi.*/)             { $cgi = 1;                 next; } # for CGI mode; ignore
    if ($arg =~ /^--yeast.?prot/)       { _yeast_prot();          exit 0; } # debugging
    if ($arg =~ /^--yeast(.*)/)         { _yeast_data();          exit 0; } # -"-
    if ($arg =~ /^--exit=(.*)/)         {                           next; } # -"-
    if ($arg =~ /^--cmd=\+?(.*)/)       { $arg = '+' . $1;                } # no next; 
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

    # Following checks use exact matches with 'eq' or regex matches with '=~'

    _y_ARG("option?  $arg");
    #{ OPTIONS
    #  NOTE that strings miss - and _ characters (see normalization above)
    #!# You may read the lines as table with columns like:
    #!#--------+------------------------+---------------------------+----------
    #!#           option to check        what to do                  comment
    #!#--------+------------------------+---------------------------+----------
    # options for trace and debug
    if ($arg =~ /^--v(erbose)?$/)       { $cfg{'verbose'}++;        }
    if ($arg =~ /^--warnings?$/)        { $cfg{'warning'}++;        }
    if ($arg =~ /^--nowarnings?$/)      { $cfg{'warning'}   = 0;    }
    if ($arg eq  '--n')                 { $cfg{'try'}       = 1;    }
    if ($arg =~ /^--tracearg/i)         { $cfg{'traceARG'}++;       } # special internal tracing
    if ($arg =~ /^--tracecmd/i)         { $cfg{'traceCMD'}++;       } # ..
    if ($arg =~ /^--trace(@|key)/i)     { $cfg{'traceKEY'}++;       } # ..
    if ($arg =~ /^--traceme/i)          { $cfg{'traceME'}++;        } # ..
    if ($arg =~ /^--tracenotme/i)       { $cfg{'traceME'}--;        } # ..
    if ($arg =~ /^--tracetime/i)        { $cfg{'traceTIME'}++;      } # ..
    if ($arg =~ /^--tracesub/i)         { $arg = '+traceSUB';       } # ..
    if ($arg eq  '--trace')             { $typ = 'TRACE';           }
    if ($arg eq  '--linux_debug')       { $cfg{'--linux_debug'}++;  }
    if ($arg eq  '--quit')              { $arg = '+quit';           }
    if ($arg eq  '--slowly')            { $cfg{'slowly'}    = 1;    }
    if ($arg =~ /^--exp(erimental)?$/)  { $cfg{'experimental'} = 1; }
    if ($arg =~ /^--noexp(erimental)?$/){ $cfg{'experimental'} = 0; }
    # proxy options
    if ($arg =~ /^--proxy(?:host)?$/)   { $typ = 'PHOST';           }
    if ($arg eq  '--proxyport')         { $typ = 'PPORT';           }
    if ($arg eq  '--proxyuser')         { $typ = 'PUSER';           }
    if ($arg eq  '--proxypass')         { $typ = 'PPASS';           }
    if ($arg eq  '--proxyauth')         { $typ = 'PAUTH';           }
    if ($arg =~ /^--?starttls$/i)       { $typ = 'STARTTLS';        }
    if ($arg =~ /^--starttlsdelay$/i)   { $typ = 'TLSDELAY';        }
    # options form other programs for compatibility
    if ($arg =~ /^--?nofailed$/)        { $cfg{'enabled'}   = 0;    } # sslscan
    if ($arg eq  '--hiderejectedciphers'){$cfg{'disabled'}  = 0;    } # ssltest.pl
    if ($arg eq  '--httpget')           { $cfg{'usehttp'}++;        } # ssltest.pl
    if ($arg eq  '--version')           { $arg = '+version';        }
    if ($arg eq  '-v')                  { $cfg{'opt-v'}     = 1;    } # openssl, sets ciphers-v, see below
    if ($arg eq  '-V')                  { $cfg{'opt-V'}     = 1;    } # openssl, sets ciphers-V, see below
    if ($arg eq  '--V')                 { $cfg{'opt-V'}     = 1;    } # for lazy people, not documented
    # options form other programs which we treat as command; see Options vs. Commands also
    if ($arg eq  '--list')              { $arg = '+list';           } # no next!
    if ($arg eq  '--chain')             { $arg = '+chain';          } # as these
    if ($arg eq  '--default')           { $arg = '+default';        } # should
    if ($arg eq  '--fingerprint')       { $arg = '+fingerprint';    } # become
    if ($arg =~ /^--resum(ption)?$/)    { $arg = '+resumption';     } # commands
    if ($arg =~ /^--reneg(otiation)?/)  { $arg = '+renegotiation';  } # ..
    if ($arg eq  '--printavailable')    { $arg = '+ciphers';        } # ssldiagnose.exe
    if ($arg eq  '--printcert')         { $arg = '+text';           } # ..
    if ($arg eq  '-i')                  { $arg = '+issuer';         } # ssl-cert-check
    if ($arg eq  '-B')                  { $arg = '+heartbleed';     } # testssl.sh
    if ($arg =~ /^-(C|-compression|-crime)$/) { $arg = '+compression';# testssl.sh
                                          push(@{$cfg{'do'}}, @{$cfg{'cmd-crime'}}); }
    if ($arg eq  '-R')                  { $arg = '+renegotiation';  } # testssl.sh
    if ($arg =~  /^--(p?fs|nsa)$/)      { $arg = '+pfs';            } # testssl.sh
    if ($arg =~  /^--(rc4|appelbaum)$/) { $arg = '+pfs';            } # testssl.sh
    if ($arg eq  '--spdy')              { $arg = '+spdy';           } # testssl.sh
    if ($arg eq  '--fips')              { $arg = '+fips';           } # 
    if ($arg eq  '--ism')               { $arg = '+ism';            } # ssltest.pl
    if ($arg eq  '--pci')               { $arg = '+pci';            } # ssltest.pl
    if ($arg =~ /^--(fips|ism|pci)$/i)  {}
    # options to handle external openssl
    if ($arg eq  '--openssl')           { $typ = 'OPENSSL';         }
    if ($arg =~  '--opensslco?nf')      { $typ = 'SSLCNF';          }
    if ($arg eq  '--opensslfips')       { $typ = 'SSLFIPS';         }
    if ($arg eq  '--extopenssl')        { $cmd{'extopenssl'}    = 1;}
    if ($arg eq  '--noopenssl')         { $cmd{'extopenssl'}    = 0;}
    if ($arg eq  '--forceopenssl')      { $cmd{'extciphers'}    = 1;}
    if ($arg =~ /^--s_?client$/)        { $cmd{'extsclient'}++;     }
    if ($arg =~ /^--?nextprotoneg$/)    { $cfg{'use_nextprot'}  = 1;}
    if ($arg =~ /^--nonextprotoneg/)    { $cfg{'use_nextprot'}  = 0;}
    if ($arg =~ /^--?tlsextdebug$/)     { $cfg{'use_extdebug'}  = 1;}
    if ($arg =~ /^--notlsextdebug/)     { $cfg{'use_extdebug'}  = 0;}
    if ($arg =~ /^--?reconnect$/)       { $cfg{'use_reconnect'} = 1;}
    if ($arg =~ /^--noreconnect$/)      { $cfg{'use_reconnect'} = 0;}
    if ($arg eq  '--sclientopt')        { $typ = 'OPT';             }
    # some options are for compatibility with other programs
    #   example: -tls1 -tlsv1 --tlsv1 --tls1_1 --tlsv1_1 --tls11 -no_SSL2
    if ($arg eq  '--regular')           { $cfg{'usehttp'}++;        } # sslyze
    if ($arg eq  '--forcesni')          { $cfg{'forcesni'}  = 1;    }
    if ($arg =~ /^--ignorenoconn(ect)?/){ $cfg{'ignore_no_conn'}= 1;}
    if ($arg eq  '--lwp')               { $cfg{'uselwp'}    = 1;    }
    if ($arg eq  '--sni')               { $cfg{'usesni'}    = 1;    }
    if ($arg eq  '--nosni')             { $cfg{'usesni'}    = 0;    }
    if ($arg eq  '--nocert')            { $cfg{'no_cert'}++;        }
    if ($arg eq  '--noignorecase')      { $cfg{'ignorecase'}= 0;    }
    if ($arg eq  '--ignorecase')        { $cfg{'ignorecase'}= 1;    }
    if ($arg =~ /^--?sslv?2$/i)         { $cfg{'SSLv2'}     = 1;    } # allow case insensitive
    if ($arg =~ /^--?sslv?3$/i)         { $cfg{'SSLv3'}     = 1;    }
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
    if ($arg eq  '-b')                  { $cfg{'out_header'}= 1;    } # ssl-cert-check
    if ($arg eq  '-V')                  { $cfg{'opt-V'}     = 1;    } # ssl-cert-check; will be out_header, see below
#   if ($arg eq  '-v')                  { $typ = 'PROTOCOL';        } # ssl-cert-check # FIXME: not supported; see opt-v and ciphers-v above
    # our options
    if ($arg eq  '--http')              { $cfg{'usehttp'}++;        }
    if ($arg eq  '--nohttp')            { $cfg{'usehttp'}   = 0;    }
    if ($arg eq  '--norc')              {                           } # simply ignore
    if ($arg eq  '--ssllazy')           { $cfg{'ssl_lazy'}  = 1;    } # ..
    if ($arg eq  '--nossllazy')         { $cfg{'ssl_lazy'}  = 0;    } # ..
    if ($arg =~ /^--nullsslv?2$/i)      { $cfg{'nullssl2'}  = 1;    } # ..
    if ($arg =~ /^--sslv?2null$/i)      { $cfg{'nullssl2'}  = 1;    } # ..
    if ($arg eq  '--nodns')             { $cfg{'usedns'}    = 0;    }
    if ($arg eq  '--dns')               { $cfg{'usedns'}    = 1;    }
    if ($arg eq  '--enabled')           { $cfg{'enabled'}   = 1;    }
    if ($arg eq  '--disabled')          { $cfg{'disabled'}  = 1;    }
    if ($arg eq  '--local')             { $cfg{'nolocal'}   = 1;    }
    if ($arg =~ /^--short(?:te?xt)?$/)  { $cfg{'shorttxt'}  = 1;    }
    if ($arg eq  '--score')             { $cfg{'out_score'} = 1;    }
    if ($arg eq  '--noscore')           { $cfg{'out_score'} = 0;    }
    if ($arg eq  '--header')            { $cfg{'out_header'}= 1;    }
    if ($arg eq  '--noheader')          { $cfg{'out_header'}= 0;    }
    if ($arg eq  '--nomd5cipher')       { $cfg{'use_md5cipher'} = 0;}
    if ($arg eq  '--md5cipher')         { $cfg{'use_md5cipher'} = 1;}
    if ($arg eq  '--tab')               { $text{'separator'}= "\t"; } # TAB character
    if ($arg eq  '--showhost')          { $cfg{'showhost'}++;       }
    if ($arg eq  '--protocol')          { $typ = 'PROTOCOL';        } # ssldiagnose.exe
#   if ($arg eq  '--serverprotocol')    { $typ = 'PROTOCOL';        } # ssldiagnose.exe; # not implemented 'cause we do not support server mode
    if ($arg =~ /^--?h(?:ost)?$/)       { $typ = 'HOST';            } # --h already catched above
    if ($arg =~ /^--?p(?:ort)?$/)       { $typ = 'PORT';            }
    if ($arg =~ /^--exe(?:path)?$/)     { $typ = 'EXE';             }
    if ($arg =~ /^--lib(?:path)?$/)     { $typ = 'LIB';             }
    if ($arg eq  '--envlibvar')         { $typ = 'ENV';             }
    if ($arg =~ /^--(?:no|ignore)out(?:put)?$/) { $typ = 'NO_OUT';  }
    if ($arg =~ /^--(?:no|ignore)cmd$/) { $typ = 'NO_OUT';          } # alias ...
    if ($arg =~ /^--cfg(.*)$/)          { $typ = 'CFG-' . $1;       } # FIXME: dangerous input
    if ($arg eq  '--call')              { $typ = 'CALL';            }
    if ($arg eq  '--cipher')            { $typ = 'CIPHER';          }
    if ($arg eq  '--cipherrange')       { $typ = 'CRANGE';          }
    if ($arg eq  '--range')             { $typ = 'CRANGE';          }
    if ($arg eq  '--format')            { $typ = 'FORMAT';          }
    if ($arg eq  '--legacy')            { $typ = 'LEGACY';          }
    if ($arg =~ /^--sep(?:arator)?$/)   { $typ = 'SEP';             }
    if ($arg =~ /^--?timeout$/)         { $typ = 'TIMEOUT';         }
    if ($arg =~ /^--?interval$/)        { $typ = 'TIMEOUT';         } # ssldiagnos.exe
    if ($arg =~ /^--nocertte?xt$/)      { $typ = 'CTXT';            }
    if ($arg =~ /^--sniname/i)          { $typ = 'SNINAME';         }
    if ($arg =~ /^--?servername/i)      { $typ = 'SNINAME';         } # -servername for openssl
    # options for Net::SSLhello
    if ($arg =~ /^--no(?:dns)?mx/)      { $cfg{'usemx'}     = 0;    }
    if ($arg =~ /^--(?:dns)?mx/)        { $cfg{'usemx'}     = 1;    }
    if ($arg eq  '--sslretry')          { $typ = 'SSLRETRY';        }
    if ($arg eq  '--ssltimeout')        { $typ = 'SSLTOUT';         }
    if ($arg eq  '--sslmaxciphers')     { $typ = 'MAXCIPHER';       }
    if ($arg eq  '--nossluseecc')       { $cfg{'sslhello'}->{'useecc'}   = 0; } # alias ...
    if ($arg eq  '--sslnouseecc')       { $cfg{'sslhello'}->{'useecc'}   = 0; }
    if ($arg eq  '--ssluseecc')         { $cfg{'sslhello'}->{'useecc'}   = 1; }
    if ($arg eq  '--nossluseecpoint')   { $cfg{'sslhello'}->{'useecpoint'} = 0; } # alias ...
    if ($arg eq  '--sslnouseecpoint')   { $cfg{'sslhello'}->{'useecpoint'} = 0; }
    if ($arg eq  '--ssluseecpoint')     { $cfg{'sslhello'}->{'useecpoint'} = 1; }
    if ($arg eq  '--nosslusereneg')     { $cfg{'sslhello'}->{'usereneg'} = 0; } # alias ...
    if ($arg eq  '--sslnousereneg')     { $cfg{'sslhello'}->{'usereneg'} = 0; }
    if ($arg eq  '--sslusereneg')       { $cfg{'sslhello'}->{'usereneg'} = 1; }
    if ($arg eq  '--nossldoublereneg')  { $cfg{'sslhello'}->{'double_reneg'}   = 0; } # alias ...
    if ($arg eq  '--sslnodoublereneg')  { $cfg{'sslhello'}->{'double_reneg'}   = 0; }
    if ($arg eq  '--ssldoublereneg')    { $cfg{'sslhello'}->{'double_reneg'}   = 1; }
    if ($arg eq  '--nodataeqnocipher')  { $cfg{'sslhello'}->{'nodatanocipher'} = 1; } # alias ...
    if ($arg eq  '--sslnodatanocipher') { $cfg{'sslhello'}->{'nodatanocipher'} = 1; }
    if ($arg eq  '--sslnodataeqnocipher'){$cfg{'sslhello'}->{'nodatanocipher'} = 1; }
    if ($arg eq  '--nosslnodatanocipher') { $cfg{'sslhello'}->{'nodatanocipher'} = 0; }
    if ($arg eq  '--nosslnodataeqnocipher'){$cfg{'sslhello'}->{'nodatanocipher'} = 0; }
    #!#--------+------------------------+---------------------------+----------
    if ($arg =~ /^--cadepth$/i)         { $typ = 'CADEPTH';         } # some tools use CAdepth
    if ($arg =~ /^--ca(?:cert(?:ificate)?|file)$/i){ $typ ='CAFILE';} # curl, openssl, wget, ...
    if ($arg =~ /^--ca(?:directory|path)$/i)       { $typ ='CAPATH';} # curl, openssl, wget, ...
    if ($arg eq  '-c')                  { $typ = 'CAPATH';          } # ssldiagnose.exe
    if ($arg =~ /^--winCR/i)            { binmode(STDOUT, ':crlf'); binmode(STDERR, ':crlf'); }
    # ignored options
    if ($arg =~ /^-connect$/)           {}
    if ($arg eq  '--insecure')          {}
    if ($arg =~ /^--use?r$/)            {}
    if ($arg =~ /^--(ciscospeshul|nocolor|nopct|strictpcigrade|UDP)$/)    {} # ssldiagnos.exe
    if ($arg =~ /^--server(cert|certkey|certpass|cipher|protocol|mode)$/) {} #  "
    if ($arg =~ /^-(H|r|s|t|url|u|U|x)$/){}
                # -s HOST   # ssl-cert-check: -s ignored hence HOST parsed as expected
                # -x DAYS   # ssl-cert-check: -x ignored hence DAYS taken as host # FIXME
    #} --------+------------------------+---------------------------+----------

    next if ($arg =~ /^-/); # all options handled, remaining are ignored
        # TODO: means that targets starting with '-' are not possible,
        #       however, such FQDN are illegal

    #{ COMMANDS
    _y_ARG("command? $arg");
    # You may read the lines as table with colums like:
    #!#+---------+----------------------+-----------------------+-----------------
    #!#           command to check       aliased to              comment/traditional name
    #!#+---------+----------------------+-----------------------+-----------------
    if ($arg eq  '+check')              { $check  = 1;          }
    if ($arg eq  '+info')               { $info   = 1;          } # needed 'cause +info and ..
    if ($arg eq  '+quick')              { $quick  = 1;          } # .. +quick convert to list of commands
    if ($arg eq  '+sni')                { $cmdsni = 1;          }
    if ($arg eq  '+http2')              { $arg = '+protocols';  } # HTTP/2.0; TODO: may be changed in future
    if ($arg eq  '+spdy')               { $arg = '+protocols';  } # spdy; TODO: may be changed in future
    if ($arg eq  '+spdy3')              { $arg = '+protocols';  } # SPDY/3.0; TODO: may be changed in future
    if ($arg eq  '+spdy31')             { $arg = '+protocols';  } # SPDY/3.1; TODO: may be changed in future
    if ($arg eq  '+spdy4')              { $arg = '+protocols';  } # SPDY/4.0; TODO: may be changed in future
    if ($arg eq  '+prots')              { $arg = '+protocols';  } # alias
    if ($arg eq  '+tlsv10')             { $arg = '+tlsv1';      } # alias
    if ($arg eq  '+dtlsv10')            { $arg = '+dtlsv1';     } # alias
    if ($arg eq  '+owner')              { $arg = '+subject';    } # subject
    if ($arg eq  '+authority')          { $arg = '+issuer';     } # issuer
    if ($arg eq  '+expire')             { $arg = '+after';      }
    if ($arg eq  '+extension')          { $arg = '+extensions'; }
    if ($arg eq  '+sts')                { $arg = '+hsts';       }
    if ($arg eq  '+sigkey')             { $arg = '+sigdump';    } # sigdump
    if ($arg eq  '+sigkey_algorithm')   { $arg = '+signame';    } # signame
    if ($arg eq  '+protocol')           { $arg = '+session_protocol'; } # alias
    if ($arg eq  '+rfc6125')            { $arg = '+rfc6125_names';    } # alias; TODO until check is improved (6/2015)
    if ($arg =~ /^\+modulus_exponent_size/)         { $arg = '+modulus_exp_size'; } # alias
    if ($arg =~ /^\+pub(lic)?_enc(ryption)?/)       { $arg = '+pub_encryption';} # alias
    if ($arg =~ /^\+pubkey_enc(ryption)?/)          { $arg = '+pub_encryption';} # alias
    if ($arg =~ /^\+public_key_encryption/)         { $arg = '+pub_encryption';} # alias
    if ($arg =~ /^\+pub(lic)?_enc(ryption)?_known/) { $arg = '+pub_enc_known'; } # alias
    if ($arg =~ /^\+pubkey_enc(ryption)?_known/)    { $arg = '+pub_enc_known'; } # alias
    if ($arg =~ /^\+sig(key)?_enc(ryption)?/)       { $arg = '+sig_encryption';} # alias
    if ($arg =~ /^\+sig(key)?_enc(ryption)?_known/) { $arg = '+sig_enc_known'; } # alias
    if ($arg =~ /^\+server[_-]?(temp)?[_-]?key/)    { $arg = '+dh_parameter';  } # alias
    if ($arg =~ /^\+reused?/i)          { $arg = '+resumption'; } # alias
    if ($arg =~ /^\+commonName/i)       { $arg = '+cn';         }
    if ($arg =~ /^\+cert(ificate)?$/i)  { $arg = '+pem';        } # PEM
    if ($arg =~ /^\+issuerX509/i)       { $arg = '+issuer';     }  # issuer
    if ($arg =~ /^\+subjectX509/i)      { $arg = '+subject';    }  # subject
    if ($arg =~ /^\+sha2sig(nature)?$/) { $arg = '+sha2signature'; }    # alias
    if ($arg =~ /^\+sni[_-]?check$/)    { $arg = '+check_sni';  }
    if ($arg =~ /^\+check[_-]?sni$/)    { $arg = '+check_sni';  }
    if ($arg =~ /^\+ext_aia/i)          { $arg = '+ext_authority'; } # AIA is a common acronym ...
    if ($arg =~ /\+vulnerabilit(y|ies)/){ $arg = '+vulns';      } # vulns
    if ($arg =~ /^\+selected[_-]?ciphers?$/){$arg= '+selected'; } # alias
    if ($arg =~ /^\+session[_-]?ciphers?$/) {$arg= '+selected'; } # alias
    if ($arg =~ /^\+(?:all|raw)ciphers?$/){ $arg = '+cipherraw';} # alias
    if ($arg =~ /^\+ciphers?(?:all|raw)$/){ $arg = '+cipherraw';} # alias
    #  +---------+----------------------+-----------------------+----------------
    #   command to check     what to do                          what to do next
    #  +---------+----------+-----------------------------------+----------------
    # commands which cannot be combined with others
    if ($arg eq  '+info')   { @{$cfg{'do'}} = (@{$cfg{'cmd-info'}},    'info'); next; }
    if ($arg eq  '+info--v'){ @{$cfg{'do'}} = (@{$cfg{'cmd-info--v'}}, 'info'); next; } # like +info ...
    if ($arg eq  '+quick')  { @{$cfg{'do'}} = (@{$cfg{'cmd-quick'}},  'quick'); next; }
    if ($arg eq  '+check')  { @{$cfg{'do'}} = (@{$cfg{'cmd-check'}},  'check'); next; }
    if ($arg eq  '+vulns')  { @{$cfg{'do'}} = (@{$cfg{'cmd-vulns'}},  'vulns'); next; }
    if ($arg eq '+check_sni'){@{$cfg{'do'}} =  @{$cfg{'cmd-sni--v'}};           next; }
    if ($arg eq '+protocols'){@{$cfg{'do'}} = (@{$cfg{'cmd-prots'}});           next; }
    if ($arg eq '+traceSUB'){
        # this command is just documentation, no need to care about other options
        print "# $mename  list of internal functions:\n";
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
        if ($val eq 'beast'){ push(@{$cfg{'do'}}, @{$cfg{'cmd-beast'}}); next; }
        if ($val eq 'crime'){ push(@{$cfg{'do'}}, @{$cfg{'cmd-crime'}}); next; }
        if ($val eq 'freak'){ push(@{$cfg{'do'}}, @{$cfg{'cmd-freak'}}); next; }
        if ($val eq 'lucky13'){ push(@{$cfg{'do'}}, @{$cfg{'cmd-lucky13'}}); next; }
        if ($val eq 'sizes'){ push(@{$cfg{'do'}}, @{$cfg{'cmd-sizes'}}); next; }
        if ($val eq 'hsts') { push(@{$cfg{'do'}}, @{$cfg{'cmd-hsts'}});  next; }
        if ($val eq 'http') { push(@{$cfg{'do'}}, @{$cfg{'cmd-http'}});  next; }
        if ($val eq 'pfs')  { push(@{$cfg{'do'}}, @{$cfg{'cmd-pfs'}});   next; }
        if ($val eq 'sni')  { push(@{$cfg{'do'}}, @{$cfg{'cmd-sni'}});   next; }
        if ($val eq 'ev')   { push(@{$cfg{'do'}}, @{$cfg{'cmd-ev'}});    next; }
        if ($val =~ /^(bsi|TR-?0(2102|3116))$/i) { push(@{$cfg{'do'}}, @{$cfg{'cmd-bsi'}}); next; }
        if (_is_member($val, \@{$cfg{'cmd-NOT_YET'}}) > 0) {
            _warn("command not yet implemented '$val' may be ignored");
        }
        if (_is_member($val, \@{$cfg{'commands'}}) == 1) {
            push(@{$cfg{'do'}}, lc($val));      # lc() as only lower case keys are allowed since 14.10.13
        } else {
            _warn("unknown command '$val' command ignored");
        }
        next;
    }
    #} +---------+----------+------------------------------------+----------------

    if ($arg =~ /(ciphers|s_client|version)/) {    # handle openssl commands special
        _warn("host-like argument '$arg' treated as command '+$arg'");
        _warn(STR_HINT . "please use '+$arg' instead");
        push(@{$cfg{'do'}}, $arg);
        next;
    }

    if ($typ eq 'HOST')     {   # host argument is the only one parsed here
        # allow URL   http://f.q.d.n:42/aa*foo=bar:23/
        $port = $arg;
        if ($port =~ m#.*?:\d+#) {                 # got a port too
            $port =~ s#(?:[^/]+/+)?([^/]*).*#$1#;  # match host:port
            $port =~ s#[^:]*:(\d+).*#$1#;
            _y_ARG("port: $port");
        } else { # use previous port
            $port = $cfg{'port'};
        }
        $arg =~ s#(?:[^/]+/+)?([^/]*).*#$1#;       # extract host from URL
        $arg =~ s#:(\d+)##;
        push(@{$cfg{'hosts'}}, $arg . ":" . $port);
        _yeast("host: $arg") if ($cfg{'trace'} > 0);
    }

} # while options and arguments

# exit if ($#{$cfg{'do'}} < 0); # no exit here, as we want some --v output

if ($cfg{'proxyhost'} ne "" && $cfg{'proxyport'} == 0) {
    my $q = "'";
    printusage_exit("$q--proxyhost=$cfg{'proxyhost'}$q requires also '--proxyport=NN'");
}
$cfg{'traceCMD'}++ if ($cfg{'traceTIME'} > 0);
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
    $cfg{'out_header'}  = 0 if (grep(/--header/, @argv) <= 0);
    $cfg{'ciphers-v'}   = $cfg{'opt-v'};
    $cfg{'ciphers-V'}   = $cfg{'opt-V'};
    $cfg{'legacy'}      = "openssl";
    $text{'separator'}  = " " if (grep(/--(?:tab|sep(?:arator)?)/, @argv) <= 0); # space if not set
} else {
    # not +ciphers command, then  -V  is for compatibility
    if (! _is_do('list')) {
        $cfg{'out_header'}  = $cfg{'opt-V'} if ($cfg{'out_header'} <= 0);
    }
}
if (_is_do('list')) {
    # our own command to list ciphers: uses header and TAB as separator
    $cfg{'out_header'}  = 1 if (grep(/--no.?header/, @argv) <= 0);
    $cfg{'ciphers-v'}   = $cfg{'opt-v'};
    $cfg{'ciphers-V'}   = $cfg{'opt-V'};
    $text{'separator'}  = "\t" if (grep(/--(?:tab|sep(?:arator)?)/, @argv) <= 0); # tab if not set
}
if (_is_do('pfs'))  { push(@{$cfg{'do'}}, 'pfs_cipherall') if (!_is_do('pfs_cipherall')); }

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
$ENV{'OPENSSL_CONF'} = $cfg{'openssl_cnf'}  if (defined $cfg{'openssl_cnf'});
$ENV{'OPENSSL_FIPS'} = $cfg{'openssl_fips'} if (defined $cfg{'openssl_fips'});

_yeast_args();
_vprintme();

usr_pre_exec();

## call with other libraries
## -------------------------------------
_y_ARG("exec? $cfg{'exec'}");
# NOTE: this must be the very first action/command
if ($cfg{'exec'} == 0) {
    # as all shared libraries used by perl modules are already loaded when
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
        $ENV{PATH} = join($chr, @{$cmd{'path'}}, $ENV{PATH})  if ($#{$cmd{'path'}} >= 0);
        $ENV{PATH} = join($chr, @{$cmd{'libs'}}, $ENV{PATH})  if ($#{$cmd{'libs'}} >= 0);
        $ENV{$cmd{envlibvar}}  = join($chr, @{$cmd{'libs'}})  if ($#{$cmd{'libs'}} >= 0);
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
_y_TIME("inc{");

local $\ = "\n";

## import common and private modules
## -------------------------------------
# Unfortunately `use autouse' is not possible as to much functions need to
# be declared for that pragma then.
use     IO::Socket::SSL 1.37;       # qw(debug2);
use     IO::Socket::INET;
if (_is_do('version') or ($cfg{'usemx'} > 0)) {
    eval("require Net::DNS;");
    if ($@ ne "") {
        chomp $@;
        _warn($@); _warn("--mx disabled");
        $cfg{'usemx'} = 0;
    }
}
if (_is_do('cipherraw') or _is_do('version')
    or ($cfg{'starttls'})
    or (($cfg{'proxyhost'}) and ($cfg{'proxyport'}))
   ) {
    $err = _load_file("Net/SSLhello.pm", "O-Saft module");  # must be found with @INC
    if ($err ne "") {
        die  STR_ERROR, "$err"  if (! _is_do('version'));
        warn STR_ERROR, "$err";     # no reason to die for +version
    }
    $cfg{'usehttp'} = 0;            # makes no sense for starttls
    # TODO: not (yet) supported for proxy
}
$err = _load_file("Net/SSLinfo.pm", "O-Saft module");       # must be found
if ($err ne "") {
    die  STR_ERROR, "$err"  if (! _is_do('version'));
    warn STR_ERROR, "$err";         # no reason to die for +version
}
_y_TIME("inc}");

## check for supported SSL versions
## -------------------------------------
_y_CMD("  check supported SSL versions ...");
foreach $ssl (@{$cfg{'versions'}}) {
    next if ($cfg{$ssl} == 0);  # don't check what's disabled by option
    if (_is_do('cipherraw')) {  # +cipherraw does not depend on other libraries
        if ($ssl eq 'DTLSv1') {
            _warn("SSL version '$ssl': not supported by '$mename +cipherraw'; not checked");
            next;
        }
        push(@{$cfg{'version'}}, $ssl);
        next;
    }
    next if ((_need_cipher() <= 0) and (_need_default() <= 0) and ! _is_do('version'));
    # following checks for these commands only
    $cfg{$ssl} = 0; # reset to simplify further checks
    if ($ssl =~ /$cfg{'regex'}->{'SSLprot'}/) {
        # Net::SSLeay only supports methods for those SSL protocols which were
        # available at the time of compiling Net::SSLeay. The support of these
        # protocols is not checked dynamically when building Net::SSLeay.
        # Net::SSLeay's  config script  simply relies on the definitions found
        # in the specified include files of the underlaying SSL library (which
        # is openssl usually).
        # Unfortunately,  there are situations where the assumtions at compile
        # time don't match the conditions at runtime. Then  Net::SSLeay  bails
        # out with error like:
        #   Can't locate auto/Net/SSLeay/CTX_v2_new.al in @INC ...
        # which means that  Net::SSLeay  was build without support for SSLv2.
        # To avoid bothering users with such messages (see above) or even more
        # erros or program aborts, we check for the availability of all needed
        # methods. Sometimes, for whatever reason,  the user may know that the
        # warning can be avoided. Therfore the  --ssl-lazy option can be used,
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
        $typ = (defined &Net::SSLeay::SSLv2_method)   ? 1:0 if ($ssl eq 'SSLv2');
        $typ = (defined &Net::SSLeay::SSLv3_method)   ? 1:0 if ($ssl eq 'SSLv3');
        $typ = (defined &Net::SSLeay::TLSv1_method)   ? 1:0 if ($ssl eq 'TLSv1');
        $typ = (defined &Net::SSLeay::TLSv1_1_method) ? 1:0 if ($ssl eq 'TLSv11');
        $typ = (defined &Net::SSLeay::TLSv1_2_method) ? 1:0 if ($ssl eq 'TLSv12');
        $typ = (defined &Net::SSLeay::TLSv1_3_method) ? 1:0 if ($ssl eq 'TLSv13');
        $typ = (defined &Net::SSLeay::DTLSv1_method)  ? 1:0 if ($ssl eq 'DTLSv1');
        $typ = (defined &Net::SSLeay::DTLSv1_1_method)? 1:0 if ($ssl eq 'DTLSv11');
        $typ = (defined &Net::SSLeay::DTLSv1_2_method)? 1:0 if ($ssl eq 'DTLSv12');
        $typ = (defined &Net::SSLeay::DTLSv1_3_method)? 1:0 if ($ssl eq 'DTLSv13');
        if ($typ == 1) {
            push(@{$cfg{'version'}}, $ssl);
            $cfg{$ssl} = 1;
        } else {
            _warn("SSL version '$ssl': not supported by Net::SSLeay; not checked");
            print STR_HINT . "consider using '+cipherall' instead" if (_is_do('cipher'));
        }
    } else {    # SSL versions not supported by Net::SSLeay <= 1.51 (Jan/2013)
        _warn("SSL version '$ssl': not supported; not checked");
    }
}
if (! _is_do('version')) {
    _v_print("supported SSL versions: @{$cfg{'versions'}}");
    _v_print("  checked SSL versions: @{$cfg{'version'}}");
}

## check if used software supports SNI properly
## -------------------------------------
if (! _is_do('cipherraw')) {        # +cipherraw does not need these checks
$typ  = "old version of ## detected which does not support SNI";
$typ .= " or is known to be buggy; SNI disabled\n";
$typ .= STR_HINT ."#opt# can be used to disables this check";
if ($IO::Socket::SSL::VERSION < 1.90) {
    if(($cfg{'usesni'} > 0) && ($cmd{'extciphers'} == 0)) {
        $cfg{'usesni'} = 0;
        my $txt = $typ; $txt =~ s/##/`IO::Socket::SSL < 1.90'/; $txt =~ s/#opt#/--force-openssl /;
        _warn($txt);
    }
}
if (Net::SSLeay::OPENSSL_VERSION_NUMBER() < 0x01000000) {
    # same as  IO::Socket::SSL->can_client_sni()
    # see section "SNI Support" in: perldoc IO/Socket/SSL.pm
    if(($cfg{'usesni'} > 0) && ($cfg{'forcesni'} == 0)) {
        $cfg{'usesni'} = 0;
        my $txt = $typ; $txt =~ s/##/`openssl < 1.0.0'/; $txt =~ s/#opt#/--force-?sni/;
        _warn($txt);
    }
}
_trace(" cfg{usesni}: $cfg{'usesni'}");

## check if Net::SSLeay is usable
## -------------------------------------
if (!defined $Net::SSLeay::VERSION) { # Net::SSLeay auto-loaded by IO::Socket::SSL
    die STR_ERROR, "Net::SSLeay not found, useless use of yet another SSL tool";
    # TODO: this is not really true, i.e. if we use openssl instead Net::SSLeay
}
if (1.49 > $Net::SSLeay::VERSION) {
    # only check VERSION instead of requiring a specific version with perl's use
    # this allows continueing to use this tool even if the version is too old
    # but we shout out loud that the results are not reliable
    _warn("ancient Net::SSLeay $Net::SSLeay::VERSION found");
    _warn("$0 requires Net::SSLeay 1.49 or newer");
    _warn("$0 may throw warnings and/or results may be missing");
}
} # ! +cipherraw

## set additional defaults if missing
## -------------------------------------
$cfg{'out_header'}  = 1 if(0 => $verbose); # verbose uses headers
$cfg{'out_header'}  = 1 if(0 => grep(/\+(check|info|quick|cipher)$/, @argv)); # see --header
$cfg{'out_header'}  = 0 if(0 => grep(/--no.?header/, @argv));   # command line option overwrites defaults above
if ($cfg{'usehttp'} == 0) {                # was explizitely set with --no-http 'cause default is 1
    # STS makes no sence without http
    _warn("STS $text{'no-http'}") if(0 => grep(/hsts/, @{$cfg{'do'}})); # check for any hsts*
}
$quick = 1 if ($cfg{'legacy'} eq 'testsslserver');
if ($quick == 1) {
    $cfg{'enabled'} = 1;
    $cfg{'shorttxt'}= 1;
}
$text{'separator'}  = "\t"    if ($cfg{'legacy'} eq "quick");

## add openssl-specific path for CAs
## -------------------------------------
if ($cmd{'extopenssl'} == 1) {
    $arg = qx($cmd{'openssl'} version -d);     # get something like: OPENSSLDIR: "/usr/local/openssl"
    my $status = $?;
    my $error  = $!;
    if (($error ne "") && ($status != 0)) {    # we ignore error messages for status==0
        # When there is a status and an error message, external call failed.
        # Print error message and disable external openssl.
        # In rare cases (i.e. VM with low memory) external call fails due to
        # malloc() problems, in this case print an additional warning.
        # Note that low memory affects external calls only *but not* further
        # control flow herein as perl already managed to load the script.
        print STR_WARN, "perl returned error: '$error'\n";
        if ($error =~ m/allocate memory/) {
            print STR_WARN, "using external programs disabled.\n";
            print STR_WARN, "data provided by external openssl may be shown as:  <<openssl>>\n";
        }
        $cmd{'extopenssl'} = 0;
        $cmd{'extsclient'} = 0;
        $status = 0;  # avoid following warning
    } else {
        # process only if no errors to avoid "Use of uninitialized value"
        $arg =~ s#[^"]*"([^"]*)"#$1#;  chomp $arg;
        if (-e "$arg/certs") {
            $cfg{'ca_path'} = "$arg/certs";
        } else {    # no directory found, add path to common paths as last resort
            unshift(@{$cfg{'ca_paths'}}, $arg);
        }
    }
    if ($status != 0) {
        print STR_WARN, "perl returned status: '$status' ('" . ($status>>8) . "')\n";
    }
    $arg = "";
}

## set defaults for Net::SSLinfo
## -------------------------------------
{
    #$IO::Socket::SSL::DEBUG     = $cfg{'trace'} if ($cfg{'trace'} > 0);
    no warnings qw(once); # avoid: Name "Net::SSLinfo::trace" used only once: possible typo at ...
    if ($cfg{'traceME'} < 1) {
        $Net::SSLinfo::trace    = $cfg{'trace'} if ($cfg{'trace'} > 0);
    }
    $Net::SSLinfo::linux_debug  = $cfg{'linux_debug'};
    $Net::SSLinfo::use_openssl  = $cmd{'extopenssl'};
    $Net::SSLinfo::use_sclient  = $cmd{'extsclient'};
    $Net::SSLinfo::openssl      = $cmd{'openssl'};
    $Net::SSLinfo::use_http     = $cfg{'usehttp'};
    $Net::SSLinfo::use_SNI      = $cfg{'sni_name'};
    $Net::SSLinfo::use_nextprot = $cfg{'use_nextprot'};
    $Net::SSLinfo::use_extdebug = $cfg{'use_extdebug'};
    $Net::SSLinfo::use_reconnect=$cfg{'use_reconnect'};
    $Net::SSLinfo::slowly       = $cfg{'slowly'};
    $Net::SSLinfo::sclient_opt  = $cfg{'sclient_opt'};
    $Net::SSLinfo::timeout_sec  = $cfg{'timeout'};
    $Net::SSLinfo::no_cert      = $cfg{'no_cert'};
    $Net::SSLinfo::no_cert_txt  = $cfg{'no_cert_txt'};
    $Net::SSLinfo::ignore_case  = $cfg{'ignorecase'};
    $Net::SSLinfo::ca_crl       = $cfg{'ca_crl'};
    $Net::SSLinfo::ca_file      = $cfg{'ca_file'};
    $Net::SSLinfo::ca_path      = $cfg{'ca_path'};
    $Net::SSLinfo::ca_depth     = $cfg{'ca_depth'};
}
if ('cipher' eq join("", @{$cfg{'do'}})) {
    $Net::SSLinfo::use_http     = 0; # if only +cipher given don't use http 'cause it may cause erros
}

## set defaults for Net::SSLhello
## -------------------------------------
if (defined $Net::SSLhello::VERSION) {
    no warnings qw(once); # avoid: Name "Net::SSLinfo::trace" used only once: possible typo at ...
    if ($cfg{'traceME'} < 1) {
        $Net::SSLhello::trace   = $cfg{'trace'};
    }
    $Net::SSLhello::traceTIME   = $cfg{'traceTIME'};
    $Net::SSLhello::experimental= $cfg{'experimental'};
    $Net::SSLhello::usesni      = $cfg{'usesni'};
    $Net::SSLhello::usemx       = $cfg{'usemx'};
    $Net::SSLhello::sni_name    = $cfg{'sni_name'};
    $Net::SSLhello::starttls    = (($cfg{'starttls'} eq "") ? 0 : 1);
    $Net::SSLhello::starttlsType= $cfg{'starttls'};
    $Net::SSLhello::starttlsDelay=$cfg{'starttlsDelay'};
    $Net::SSLhello::timeout     = $cfg{'sslhello'}->{'timeout'};
    $Net::SSLhello::retry       = $cfg{'sslhello'}->{'retry'};
    $Net::SSLhello::max_ciphers = $cfg{'sslhello'}->{'maxciphers'};
    $Net::SSLhello::usereneg    = $cfg{'sslhello'}->{'usereneg'};
    $Net::SSLhello::useecc      = $cfg{'sslhello'}->{'useecc'};
    $Net::SSLhello::useecpoint  = $cfg{'sslhello'}->{'useecpoint'};
    $Net::SSLhello::double_reneg= $cfg{'sslhello'}->{'double_reneg'};
    $Net::SSLhello::noDataEqNoCipher= $cfg{'sslhello'}->{'nodatanocipher'};
    $Net::SSLhello::proxyhost   = $cfg{'proxyhost'};
    $Net::SSLhello::proxyport   = $cfg{'proxyport'};
    $Net::SSLhello::cipherrange = $cfg{'cipherrange'};  # not really necessary, see below
}
$cfg{'trace'} = 0 if ($cfg{'traceME'} < 0);

if ($cfg{'shorttxt'} > 0) {     # reconfigure texts
    foreach $key (keys %data)   { $data{$key}  ->{'txt'} = $shorttexts{$key}; }
    foreach $key (keys %checks) { $checks{$key}->{'txt'} = $shorttexts{$key}; }
}

# set environment

## first: all commands which do not make a connection
## -------------------------------------
printciphers(),     exit 0  if (_is_do('list'));
printciphers(),     exit 0  if (_is_do('ciphers'));
printversion(),     exit 0  if (_is_do('version'));
printopenssl(),     exit 0  if (_is_do('libversion'));
printquit(),        exit 0  if (_is_do('quit'));# internal test command

if (($cfg{'trace'} + $cfg{'verbose'}) >  0) {   # +info command is special with --v
    @{$cfg{'do'}} = @{$cfg{'cmd-info--v'}} if (@{$cfg{'do'}} eq @{$cfg{'cmd-info'}});
}
_yeast_init();

if ($#{$cfg{'do'}} < 0) {
    _yeast_exit();
    printusage_exit("no command given");
}

usr_pre_cipher();

# get list of ciphers available for tests
if (_need_cipher() > 0) {
    _y_CMD("  get cipher list ..");
    my $pattern = $cfg{'cipherpattern'};# default pattern
       $pattern = join(":", @{$cfg{'cipher'}}) if (scalar(@{$cfg{'cipher'}}) > 0);
    _trace(" cipher pattern= $pattern");
    if ($cmd{'extciphers'} == 1) {
        @{$cfg{'ciphers'}} = Net::SSLinfo::cipher_local($pattern);
    } else {
        @{$cfg{'ciphers'}} = Net::SSLinfo::cipher_list( $pattern);
    }
    _trace(" got ciphers: @{$cfg{'ciphers'}}");
    if (@{$cfg{'ciphers'}} < 0) {       # empty list, try openssl and local list
        _warn("given pattern '$pattern' did not return cipher list");
        _y_CMD("  get cipher list using openssl ..");
        @{$cfg{'ciphers'}} = Net::SSLinfo::cipher_local($pattern);
        if (@{$cfg{'ciphers'}} < 0) {   # empty list, try own list
            #if ($pattern =~ m/(NULL|COMP|DEF|HIG|MED|LOW|PORT|:|@|!|\+)/) {
            #    _trace(" cipher match: $pattern");
            #} else {
            #    _trace(" cipher privat: $pattern");
_dbx "\n########### fix this place (empty cipher list) ########\n";
# TODO: #10jan14: reimplement this check when %ciphers has a new structure
            #10jan14        $new = get_cipher_name($c);
        }
    }
    if (@{$cfg{'ciphers'}} < 0) {
        print "Errors: " . Net::SSLinfo::errors();
        die(STR_ERROR, "no ciphers found; may happen with openssl pre 1.0.0 according given pattern");
    }
}
_v_print("cipher list: @{$cfg{'ciphers'}}");

_y_EXIT("exit=MAIN  - start");
usr_pre_main();

## main: do the work for all targets
## -------------------------------------

# defense, user-friendly programming
  # could do these checks earlier (after setting defaults), but we want
  # to keep all checks together for better maintenace
printusage_exit("no target hosts given") if ($#{$cfg{'hosts'}} < 0); # does not make any sense
if (_is_do('cipher')) {
    if ($#{$cfg{'done'}->{'arg_cmds'}} > 0) {
        printusage_exit("additional commands in conjuntion with '+cipher' are not supported; '+" . join(" +", @{$cfg{'done'}->{'arg_cmds'}}) ."'");
    }
}
if (($info > 0) and ($#{$cfg{'done'}->{'arg_cmds'}} >= 0)) {
    # +info does not allow additional commands
    # see printchecks() call below
    _warn("additional commands in conjuntion with '+info' are not supported; '+" . join(" +", @{$cfg{'done'}->{'arg_cmds'}}) . "' ignored");
}
if (($check > 0) and ($#{$cfg{'done'}->{'arg_cmds'}} >= 0)) {
    # +check does not allow additional commands of type "info"
    foreach $key (@{$cfg{'done'}->{'arg_cmds'}}) {
        if (_is_member( $key, \@{$cfg{'cmd-info'}}) > 0) {
            _warn("additional commands in conjuntion with '+check' are not supported; +'$key' ignored");
        }
    }
}

# now commands which do make a connection
usr_pre_host();

my $fail = 0;
# check if output disabled for given/used commands
foreach $key (@{$cfg{'ignore-out'}}) {
    $fail++ if (_is_do($key) > 0);
}
if ($fail > 0) {
    _warn("output for some data and checks disbaled due to use of '--no-out':");
    _warn("  +" . join(" +", @{$cfg{'ignore-out'}}));
}

# run the appropriate SSL tests for each host (ugly code down here):
$port = ($cfg{'port'}||"");     # defensive programming
foreach $host (@{$cfg{'hosts'}}) {  # loop hosts
    $cfg{'host'}      = $host;
    if ($host =~ m#.*?:\d+#) {  # split host:port
       ($host, $port) = split(":", $host);
        $cfg{'port'}  = $port;  #
        $cfg{'host'}  = $host;
    }
    _y_CMD("host " . ($host||"") . ":$port {");
    _trace(" host: $host {\n");
    _resetchecks();
    printheader(_subst($text{'out-target'}, "$host:$port"), "");

    # prepare DNS stuff
    #  gethostbyname() and gethostbyaddr() set $? on error, needs to be reset!
    my $rhost = "";
    $fail = "";
    $? = 0;
    if ($cfg{'proxyhost'} ne "") {
        # if a proxy is used, DNS might not work at all, or be done by the
        # proxy (which even may return other results than the local client)
        # so we set corresponding values to a warning
        $fail = _subst($text{'disabled'}, "--proxyhost=$cfg{'proxyhost'}");
        $cfg{'rhost'}   = $fail;
        $cfg{'DNS'}     = $fail;
        $cfg{'IP'}      = $fail;
        $cfg{'ip'}      = $fail;
    } else {
        $fail  = '<<gethostbyaddr() failed>>';
        $cfg{'ip'}      = gethostbyname($host); # primary IP as identified by given hostname
        if (!defined $cfg{'ip'}) {
            _warn("Can't get IP for host '$host'; host ignored");
            _y_CMD("host}");
            next; # otherwise all following fails
        }
        # gethostbyaddr() is strange: returns $?==0 but an error message in $!
        # hence just checking $? is not reliable, we do it additionally.
        # If gethostbyaddr()  fails we use perl's  `or'  to assign our default
        # text.  This may happen when there're problems with the local name
        # resolution.
        # When gethostbyaddr() fails, the connection to the target most likely
        # fails also, which produces more perl warnings later.
        $cfg{'IP'}          = join(".", unpack("W4", $cfg{'ip'}));
        if ($cfg{'usedns'} == 1) {  # following settings only with --dns
           ($cfg{'rhost'}   = gethostbyaddr($cfg{'ip'}, AF_INET)) or $cfg{'rhost'} = $fail;
            $cfg{'rhost'}   = $fail if ($? != 0);
        }
        $? = 0;
        if ($cfg{'usedns'} == 1) {
            my ($fqdn, $aliases, $addrtype, $length, @ips) = gethostbyname($host);
            my $i = 0;
            foreach my $ip (@ips) {
                $! = 0;
                $? = 0;
               ($rhost  = gethostbyaddr($ip, AF_INET)) or $rhost = $fail;
                $rhost  = $fail if ($? != 0);
                $cfg{'DNS'} .= join(".", unpack("W4", $cfg{'ip'})) . " " . $rhost . "; ";
                #dbx# printf "[%s] = %s\t%s\n", $i, join(".",unpack("W4",$ip)), $rhost;
            }
            _warn("Can't do DNS reverse lookup: for $host: $fail; ignored") if ($cfg{'rhost'} =~ m/gethostbyaddr/);
        }
    }
    $? = 0;

    # print DNS stuff
    if (($info + $check + $cmdsni) > 0) {
        _y_CMD("+info || +check || +sni*");
        if ($legacy =~ /(full|compact|simple)/) {
            printruler();
            print_line($legacy, $host, $port, 'host-host', $text{'host-host'}, $host);
            print_line($legacy, $host, $port, 'host-IP',   $text{'host-IP'}, $cfg{'IP'});
            if ($cfg{'usedns'} == 1) {
                print_line($legacy, $host, $port, 'host-rhost', $text{'host-rhost'}, $cfg{'rhost'});
                print_line($legacy, $host, $port, 'host-DNS',   $text{'host-DNS'},   $cfg{'DNS'});
            }
            printruler();
        }
    }

    if (_is_do('cipherraw')) {
        _y_CMD("+cipherraw");
        _v_print("cipher range: $cfg{'cipherrange'}");
        foreach $ssl (@{$cfg{'version'}}) {
            next if ($cfg{$ssl} == 0);
            my @all;
            my $range = $cfg{'cipherrange'};            # use specified range of constants
               $range = 'SSLv2' if ($ssl eq 'SSLv2');   # but SSLv2 needs its own list
            push(@all, sprintf("0x%08X",$_)) foreach (eval($cfg{'cipherranges'}->{$range}));
            _v_print( "number of ciphers: " . scalar(@all));
            printtitle($legacy, $ssl, $host, $port);
            if ($Net::SSLhello::usesni >= 1) { # always test first without SNI
                $Net::SSLhello::usesni = 0;
                Net::SSLhello::printCipherStringArray(
                    'compact', $host, $port, $ssl, 0,
                    Net::SSLhello::checkSSLciphers($host, $port, $ssl, @all)
                );
                $Net::SSLhello::usesni = $cfg{'usesni'}; # restore
                next if ($ssl eq 'SSLv2');  # SSLv2 has no SNI
                next if ($ssl eq 'SSLv3');  # SSLv3 has originally no SNI 
            }
            Net::SSLhello::printCipherStringArray(
                'compact', $host, $port, $ssl, $Net::SSLhello::usesni,
                Net::SSLhello::checkSSLciphers($host, $port, $ssl, @all)
            );
        }
        next;
    }

    usr_pre_info();

    _y_CMD("get no SNI ..");
    # check if SNI supported, also copy some data to %data0
        # to do this, we need a clean SSL connection with SNI disabled
        # see SSL_CTRL_SET_TLSEXT_HOSTNAME in NET::SSLinfo
        # finally we close the connection to be clean for all other tests
    _trace(" cn_nosni: {");
    $Net::SSLinfo::use_SNI  = 0;
    if (defined Net::SSLinfo::do_ssl_open($host, $port, (join(" ", @{$cfg{'version'}})), join(" ", @{$cfg{'ciphers'}}))) {
        $data{'cn_nosni'}->{val}        = $data{'cn'}->{val}($host, $port);
        $data0{'session_ticket'}->{val} = $data{'session_ticket'}->{val}($host);
# FIXME: following disabled due to multipe openssl calls which may produce 
#         unexpected results (10/2015) {
#        foreach $key (keys %data) { # copy to %data0
#            $data0{$key}->{val} = $data{$key}->{val}($host, $port);
#        }
# }
        Net::SSLinfo::do_ssl_close($host, $port);
    } else {
        _warn("Can't make a connection to $host:$port; no initial data");
    }
    $Net::SSLinfo::use_SNI  = $cfg{'sni_name'};
    _trace(" cn_nosni: $data{'cn_nosni'}->{val}  }");

    usr_pre_open();

    # TODO dirty hack, check with dh256.tlsfun.de
    # checking for DH parameters does not need a default connection
    if (_is_do('cipher-dh')) {
        printciphers_dh($legacy, $host, $port);
        goto CLOSE_SSL;
    }

    # Check if there is something listening on $host:$port
    if ($cfg{'ignore_no_conn'} <= 0) {
        # use Net::SSLinfo::do_ssl_open() instead of IO::Socket::INET->new()
        # to check the connection (hostname and port)
        if (!defined Net::SSLinfo::do_ssl_open($host, $port, (join(" ", @{$cfg{'version'}})), join(" ", @{$cfg{'ciphers'}}))) {
            my $err = Net::SSLinfo::errors( $host, $port);
            if ($err !~ /^\s*$/) {
                _v_print($err);
                _warn("Can't make a connection to $host:$port; target ignored");
                _warn(STR_HINT ."--ignore-no-conn can be used to disables this check");
                goto CLOSE_SSL;
            }
        }
    }

    if ((_need_default() > 0) or ($check > 0)) {
        _y_CMD("get default ..");
        foreach $ssl (keys %prot) { # all protocols, no need to sort them
            next if (!defined $prot{$ssl}->{opt});
            next if (($ssl eq "SSLv2") && ($cfg{$ssl} == 0));   # avoid warning if protocol disabled: cannot get default cipher
            # no need to check for "valid" $ssl (like DTLSfamily), done by _get_default()
            my $cipher  = _get_default($ssl, $host, $port);
            $prot{$ssl}->{'default'}    = $cipher;
            $prot{$ssl}->{'pfs_cipher'} = $cipher if ("" eq _ispfs($ssl, $cipher));
        }
    }

    usr_pre_cmds();

    if (_is_do('dump')) {
        _y_CMD("+dump");
        if ($cfg{'trace'} > 1) {   # requires: --v --trace --trace
            _trace(' ############################################################ %SSLinfo');
            print Net::SSLinfo::dump();
        }
        printdump($legacy, $host, $port);
    }

    if (_need_cipher() > 0) {
        _y_CMD("  need_cipher ..");
        _y_CMD("  use socket ..")  if (0 == $cmd{'extciphers'});
        _y_CMD("  use openssl ..") if (1 == $cmd{'extciphers'});
        @results = ();          # new list for every host
        $checks{'cnt_totals'}->{val} = 0;
#dbx# print "# C", @{$cfg{'ciphers'}};
# FIXME: 6/2015 es kommt eine Fehlermeldung wenn openssl 1.0.2 verwendet wird:
# Use of uninitialized value in subroutine entry at /usr/share/perl5/IO/Socket/SSL.pm line 562.
# hat mit den Ciphern aus @{$cfg{'ciphers'}} zu tun
#    IDEA-CBC-MD5 RC2-CBC-MD5 DES-CBC3-MD5 RC4-64-MD5 DES-CBC-MD5 :
# Ursache in _usesocket() das benutzt IO::Socket::SSL->new()
        foreach $ssl (@{$cfg{'version'}}) {
            my @supported = ciphers_get($ssl, $host, $port, \@{$cfg{'ciphers'}});
            foreach my $c (@{$cfg{'ciphers'}}) {  # might be done more perlish ;-)
                push(@results, [$ssl, $c, (grep(/^$c/, @supported)>0) ? "yes" : "no"]);
                $checks{'cnt_totals'}->{val}++;
            }
        }
        checkciphers($host, $port);
     }

    usr_pre_data();

    # check ciphers manually (required for +check also)
    if (_is_do('cipher') or $check > 0) {
        _y_CMD("+cipher");
        _trace(" ciphers: @{$cfg{'ciphers'}}");
        # TODO: for legacy==testsslserver we need a summary line like:
        #      Supported versions: SSLv3 TLSv1.0
        my $_printtitle = 0;    # count title lines; 0 = no ciphers checked
        foreach $ssl (@{$cfg{'version'}}) {
            $_printtitle++;
            if (($legacy ne "sslscan") or ($_printtitle <= 1)) {
                printtitle($legacy, $ssl, $host, $port);
            }
            printciphercheck($legacy, $ssl, $host, $port, ($legacy eq "sslscan")?($_printtitle):0, @results);
        }
        foreach $ssl (@{$cfg{'version'}}) {
            print_cipherdefault($legacy, $ssl, $host, $port) if ($legacy eq 'sslscan');
        }
        if ($_printtitle > 0) { # if we checked for ciphers
            printheader("\n" . _subst($text{'out-summary'}, ""), "");
            printprotocols($legacy, $host, $port);
            printruler() if ($quick == 0);
        }
    }

    goto CLOSE_SSL if ((_is_do('cipher') > 0) and ($quick == 0));

    if (_need_checkssl() > 0) {
        _y_CMD("  need_checkssl ..");
        _trace(" checkssl {");
        checkssl( $host, $port);
        _trace(" checkssl }");
     }

    # following sequence important!
    _y_CMD("get checks ..");
    checkhttp( $host, $port); # may be already done in checkssl()
    checksni(  $host, $port); #  "
    checksizes($host, $port); #  "
    checkdv(   $host, $port); #  "
    checkdest( $host, $port);
    checkprot( $host, $port);
    checkbleed($host, $port); # vulnerable TLS heartbeat extentions

    usr_pre_print();

    if ($check > 0) {
        _y_CMD("+check");
        _warn("no openssl, some checks are missing") if (($^O =~ m/MSWin32/) and ($cmd{'extopenssl'} == 0));
    }

    # for debugging only
    if (_is_do('s_client')) { _y_CMD("+s_client"); print "#{\n", Net::SSLinfo::s_client($host, $port), "\n#}"; }
    _y_CMD("do=".join(" ",@{$cfg{'do'}}));

    # print all required data and checks
    # NOTE: if key (aka given command) exists in %checks and %data it will be printed twice
    printdata(  $legacy, $host, $port) if ($check == 0); # not for +check
    printchecks($legacy, $host, $port) if ($info  == 0); # not for +info

    if ($cfg{'out_score'} > 0) { # no output for +info also
        _y_CMD("scores");
        scoring($host, $port);
        # simple rounding in perl: $rounded = int($float + 0.5)
        $scores{'checks'}->{val} = int(
            ((
              $scores{'check_cert'}->{val}
            + $scores{'check_conn'}->{val}
            + $scores{'check_dest'}->{val}
            + $scores{'check_http'}->{val}
            + $scores{'check_size'}->{val}
            ) / 5 ) + 0.5);
        printheader($text{'out-scoring'}."\n", $text{'desc-score'});
        print "\n";
        _trace_cmd('%scores');
        foreach $key (sort keys %scores) {
            next if ($key !~ m/^check_/); # print totals only
            print_line($legacy, $host, $port, $key, $scores{$key}->{txt}, $scores{$key}->{val});
        }
        print_line($legacy, $host, $port, 'checks', $scores{'checks'}->{txt}, $scores{'checks'}->{val});
        printruler();
        print "\n";
        if (($cfg{'traceKEY'} > 0) && ($verbose > 0)) {
            _y_CMD("verbose score table");
            printtable('score');
            printruler();
        }
        print "\n";
    }

    CLOSE_SSL:
    _y_CMD("host}");
    {
      no warnings qw(once);
      if (defined $Net::SSLinfo::socket) { # check to avoid: WARNING undefined Net::SSLinfo::socket
        Net::SSLinfo::do_ssl_close($host, $port);
      }
    }
    _trace(" host: $host }\n");
    $cfg{'done'}->{'hosts'}++;

    usr_pre_next();

} # foreach host

usr_pre_exit();
_yeast_exit();
exit 0; # main

__END__
__DATA__
documentation please see o-saft-man.pm
