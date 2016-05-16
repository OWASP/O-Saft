#!/usr/bin/perl -w
# Filename: error_handler.pm
#!#############################################################################
#!#                    Copyright (c) Torsten Gigler
#!#   This script is part of the OWASP-Project 'o-saft'.
#!#   It's a simple library 'OSaft::error_handler' stores and optionally
#!#   prints all classified errors for other parts of o-saft.
#!#----------------------------------------------------------------------------
#!#   THIS Software is in ALPHA state, please give us feed back via
#!#   https://lists.owasp.org/mailman/listinfo/o-saft
#!#----------------------------------------------------------------------------
#!#   This software is provided "as is", without warranty of any kind, express or
#!#   implied,  including  but not limited to  the warranties of merchantability,
#!#   fitness for a particular purpose.  In no event shall the  copyright holders
#!#   or authors be liable for any claim, damages or other liability.
#!#   This software is distributed in the hope that it will be useful.
#!#
#!#   This  software is licensed under GPLv2.
#!#
#!#   GPL - The GNU General Public License, version 2
#!#      as specified in:  http://www.gnu.org/licenses/gpl-2.0
#!#      or a copy of it https://github.com/OWASP/O-Saft/blob/master/LICENSE.md
#!#   Permits anyone the right to use and modify the software without limitations
#!#   as long as proper  credits are given  and the original  and modified source
#!#   code are included. Requires  that the final product, software derivate from
#!#   the original  source or any  software  utilizing a GPL  component, such  as
#!#   this, is also licensed under the same GPL license.
#!#############################################################################
#!# WARNING:
#!#   This is no "academically" certified code,  but written to be understood and
#!#   modified by humans (you:) easily.  Please see the documentation  in section
#!#   "Program Code" at the end of this file if you want to improve the program.
#!#############################################################################

#?#############################################################################
#? package 'error_handler' stores and optionally prints all classified errors.
#? The latest error can be called back, eg. if the last retry missed.
#? This package uses static class methods and static data within the handler
#? to store and read the last error.
#? To use it call 'use OSaft::error_handler qw(:subs :sslhello_constants)'
#? exported subs:
#?     error_handler->new({<hash-key>=><value>}); set new values for a new error
#?         with <hash-key>=
#?             type:    no error (OERR_NO_ERROR(=1)) or type of the error(<0)
#?                      (see sslhello_constants, constant OERR_...), needs to be
#?                      a more severe error than the stored error type (=smaller value)
#?             module:  text: module or package of the caller where the error occured
#?             sub      text: sub of the caller where the error occored
#?             id       text: id inside the sub to identify the exact location where
#?                            the error occured
#?             message: text: error message providede by the caller
#?             print:   1: prints a standardized warning to stdout; 0: no output (default)
#?             warn:    1: prints a standardized warning to stderr; 0: no output (default)
#?             trace:   1: prints a standardized trace to stdouti (default); 0: no output
#?     error_handler->reset_err(<hash_ref (optional)>):
#?                                                reset the last error, optionally set a new error using hash_ref
#?     error_handler->is_err():                   returns '1' if an error has occured
#?     error_handler->get_err_type():             get (internal) number of the last error type
#?     error_handler->get_err_type_name():        get name of the last error type
#?     error_handler->get_err_val():              get a value of the error hash
#?     error_handler->get_err_str():              get and print an error message
#?
#? mainly used for testing and debugging:
#?     error_handler->get_err_hash(<prefix>, <hash_ref (optional)>):
#?                                                get the error hash as string, <prefix> is an optional prefix after a new
#?                                                line (e.g. some spaces for the indent),
#?                                                if the optional 'hash_ref' is valid this hash is used
#?     error_handler->get_all_err_types():        get all possible defined error types and their internal representation
#?                                                as a string
#? ----------------------------------------------------------------------------
#? constants:
#? sslhello_contants:                             CONSTANTS used for SSLHello: import them using 
#?                                                'use OSaft::error_handler qw(:subs :sslhello_constants)'
#?#############################################################################

package OSaft::error_handler;

use strict;
use warnings;
use Carp;

use Exporter qw(import);

use constant {
    # the version number of this package
    OERR_VERSION                                    => '16.05.16',

    # error types (general)
    OERR_NO_ERROR                                   =>     1,   # no error
    OERR_UNKNOWN_TYPE                               => -9999,   # unknown error type, needs to be the most fatal error (=smallest number)

    # error texts
    OERR_UNDEFINED_TXT                              => "<<undefined>>",
    OERR_UNKNOWN_TXT                                => "<<unknown>>",

    #special error types for SSLhello, the smaller value is more severe (they may be changed here if needed)
    OERR_SSLHELLO_ABORT_PROGRAM                     => -9000,   # error: abort running this program -> exit
    OERR_SSLHELLO_ABORT_HOST                        =>   -99,   # error: abort testing this host
    OERR_SSLHELLO_RETRY_HOST                        =>   -94,   # error: retry testing this host
    OERR_SSLHELLO_ABORT_PROTOCOL                    =>   -89,   # error: abort testing this protocol for this host
    OERR_SSLHELLO_RETRY_PROTOCOL                    =>   -84,   # error: retry testing this protocol for this host
    OERR_SSLHELLO_ABORT_CIPHERS                     =>   -79,   # error: abort testing this cipher(s) for this protocol
    OERR_SSLHELLO_RETRY_CIPHERS                     =>   -74,   # error: retry testing this cipher(s) for this protocol
    OERR_SSLHELLO_ABORT_EXTENSIONS                  =>   -69,   # error: abort testing this extensions for this ciphers
    OERR_SSLHELLO_RETRY_EXTENSIONS                  =>   -64,   # error: retry testing this extensions for this ciphers
    OERR_SSLHELLO_TEST_EXTENSIONS                   =>   -59,   # test all possible values for listed extensions
    OERR_SSLHELLO_RETRY_RECORD                      =>   -49,   # error: retry to send this record (e.g. DTLS)
    OERR_SSLHELLO_MERGE_RECORD_FRAGMENTS            =>   -39,   # try to merge fragmented record
    OERR_SSLHELLO_MERGE_DTLS                        =>   -29,   # try to merge fragmented DTLS packets
    OERR_SSLHELLO_ERROR_MESSAGE_IGNORED             =>    -1,   # error message ignored
};

our @EXPORT_OK =  ( qw(
    new is_err get_err_str reset_err get_err_val get_err_type get_err_type _name get_err_hash get_all_err_types version
    OERR_VERSION
    OERR_UNKNOWN_TYPE
    OERR_NO_ERROR
    OERR_UNDEFINED_TXT
    OERR_UNKNOWN_TXT
    OERR_SSLHELLO_ABORT_PROGRAM
    OERR_SSLHELLO_ABORT_HOST
    OERR_SSLHELLO_RETRY_HOST
    OERR_SSLHELLO_ABORT_PROTOCOL
    OERR_SSLHELLO_RETRY_PROTOCOL
    OERR_SSLHELLO_ABORT_CIPHERS
    OERR_SSLHELLO_RETRY_CIPHERS
    OERR_SSLHELLO_ABORT_EXTENSIONS
    OERR_SSLHELLO_RETRY_EXTENSIONS
    OERR_SSLHELLO_TEST_EXTENSIONS
    OERR_SSLHELLO_RETRY_RECORD
    OERR_SSLHELLO_MERGE_RECORD_FRAGMENTS
    OERR_SSLHELLO_MERGE_DTLS
    OERR_SSLHELLO_ERROR_MESSAGE_IGNORED
   )
);

our %EXPORT_TAGS =  (
    subs =>             [qw(new is_err get_err_str reset_err get_err_val 
                            get_err_type get_err_type_name get_err_hash get_all_err_types
    )],                                                         #all subs besides 'version'
    sslhello_contants => [qw(
        OERR_VERSION
        OERR_NO_ERROR
        OERR_UNKNOWN_TYPE
        OERR_UNDEFINED_TXT
        OERR_UNKNOWN_TXT
        OERR_SSLHELLO_ABORT_PROGRAM
        OERR_SSLHELLO_ABORT_HOST
        OERR_SSLHELLO_RETRY_HOST
        OERR_SSLHELLO_ABORT_PROTOCOL
        OERR_SSLHELLO_RETRY_PROTOCOL
        OERR_SSLHELLO_ABORT_CIPHERS
        OERR_SSLHELLO_RETRY_CIPHERS
        OERR_SSLHELLO_ABORT_EXTENSIONS
        OERR_SSLHELLO_RETRY_EXTENSIONS
        OERR_SSLHELLO_TEST_EXTENSIONS
        OERR_SSLHELLO_RETRY_RECORD
        OERR_SSLHELLO_MERGE_RECORD_FRAGMENTS
        OERR_SSLHELLO_MERGE_DTLS
        OERR_SSLHELLO_ERROR_MESSAGE_IGNORED
    )],
);

# reverse hash to show the names of the used constants in the modules that use this package
my $ERROR_TYPE_RHASH_REF = { 
   (OERR_NO_ERROR)                                  => 'OERR_NO_ERROR',
   (OERR_UNKNOWN_TYPE)                              => 'OERR_UNKNOWN_TYPE',
   (OERR_SSLHELLO_ABORT_PROGRAM)                    => 'OERR_SSLHELLO_ABORT_PROGRAM',
   (OERR_SSLHELLO_ABORT_HOST)                       => 'OERR_SSLHELLO_ABORT_HOST',
   (OERR_SSLHELLO_RETRY_HOST)                       => 'OERR_SSLHELLO_RETRY_HOST',
   (OERR_SSLHELLO_ABORT_PROTOCOL)                   => 'OERR_SSLHELLO_ABORT_PROTOCOL',
   (OERR_SSLHELLO_RETRY_PROTOCOL)                   => 'OERR_SSLHELLO_RETRY_PROTOCOL',
   (OERR_SSLHELLO_ABORT_CIPHERS)                    => 'OERR_SSLHELLO_ABORT_CIPHERS',
   (OERR_SSLHELLO_RETRY_CIPHERS)                    => 'OERR_SSLHELLO_RETRY_CIPHERS',
   (OERR_SSLHELLO_ABORT_EXTENSIONS)                 => 'OERR_SSLHELLO_ABORT_EXTENSIONS',
   (OERR_SSLHELLO_RETRY_EXTENSIONS)                 => 'OERR_SSLHELLO_RETRY_EXTENSIONS',
   (OERR_SSLHELLO_TEST_EXTENSIONS)                  => 'OERR_SSLHELLO_TEST_EXTENSIONS',
   (OERR_SSLHELLO_RETRY_RECORD)                     => 'OERR_SSLHELLO_RETRY_RECORD',
   (OERR_SSLHELLO_MERGE_RECORD_FRAGMENTS)           => 'OERR_SSLHELLO_MERGE_RECORD_FRAGMENTS',
   (OERR_SSLHELLO_MERGE_DTLS)                       => 'OERR_SSLHELLO_MERGE_DTLS',
   (OERR_SSLHELLO_ERROR_MESSAGE_IGNORED)            => 'OERR_SSLHELLO_ERROR_MESSAGE_IGNORED',
};

# static hash object to store the last error
my %err_hash = (
        type      => OERR_NO_ERROR,
        module    => "",
        sub       => OERR_UNDEFINED_TXT,
        id        => "",
        message   => OERR_UNDEFINED_TXT,
        print     => 0,
        warn      => 0,
        trace     => 1,
);


#?---------------------------------------------------------------------------------------
#? sub version ()
#? prints the official version number of error_handler (yy-mm-dd)
sub version {
    local $\ = ""; # no auto '\n' at the end of the line
    print "OSaft::error_handler (". OERR_VERSION .")\n";
    return;
}


#?---------------------------------------------------------------------------------------
#? sub _compile_err_str (;$)
#? internal sub that compiles a string ($err_str) based on the hash keys of $err_hash
#? $err_hash{type} should be defined and known. If it isn't the err_string remarks this lack
#? all other hash keys are suppressed if they do not exist or are not defined
#? no input variables needed
#? if the optional variable 'hash_ref' is used, the referenced hash is used instead of the $err_hash

sub _compile_err_str {
    my ($arg_ref) = @_;                                         # $arg_ref is optional, internal function: no $class!

    unless (defined ($arg_ref) && ($arg_ref)) {                 # use \$err_hash if $arg_ref is not defined (default)
        $arg_ref = \%err_hash;
    }  elsif ($err_hash{trace}) {
        print "    \$arg_ref defined: $arg_ref\n";
    }

    my $err_str="";
    $err_str  = $arg_ref->{module}                          if ( (exists ($arg_ref->{module}))  && (defined ($arg_ref->{module}))  );
    $err_str .= "::".$arg_ref->{sub}                        if ( (exists ($arg_ref->{sub}))     && (defined ($arg_ref->{sub}))     );
    $err_str .= " (".$arg_ref->{id}."):"                    if ( (exists ($arg_ref->{id}))      && (defined ($arg_ref->{id}))      );
    $err_str .= " ".$arg_ref->{message}                     if ( (exists ($arg_ref->{message})) && (defined ($arg_ref->{message})) );
    if ( (exists ($arg_ref->{type})) && (defined ($arg_ref->{type})) ) {    # type key is used
        # check if is type is known (defind in the reverse hash):
        if ( (exists ($ERROR_TYPE_RHASH_REF->{$arg_ref->{type}})) && (defined ($ERROR_TYPE_RHASH_REF->{$arg_ref->{type}})) ) {
            if ( (exists ($arg_ref->{trace})) && ($arg_ref->{trace}>0) ) {  # show the type if trace is used
                $err_str .= " [Type=".$ERROR_TYPE_RHASH_REF->{$arg_ref->{type}};
                $err_str .= "(".$arg_ref->{type}.")"        if ( $arg_ref->{trace}>2 );
                $err_str .= "]";
            } # end trace
        } else {                                                            # unknown type (not defined in ERROR_TYPE_RHASH_REF)
            $err_str .= " [Type= ".(OERR_UNKNOWN_TXT)." (".$arg_ref->{type}.")]";
        }
    } else {                                                                # undefined type
        $err_str .= " [Type=".(OERR_UNDEFINED_TXT)."]";
    }
    return ($err_str);
}


#?---------------------------------------------------------------------------------------
#? sub new($$):
#? set default values of an error hash and set values for received elements
#? parameters:
#? $class:      is added automatically when this method is used
#? $arg_ref:    the referenced hash ovwerwrites the $err_hash if its type is more fatal than the old type
sub new {
    my ($class, $arg_ref) = @_;                                 # $class is not used
    my $tmp_err_str       = "";

    # error handling inside error handling:
    # undefined/unknown error type in static err_hash
    unless ( (exists ($ERROR_TYPE_RHASH_REF->{$err_hash{type}})) && (defined ($ERROR_TYPE_RHASH_REF->{$err_hash{type}})) ) {
        $tmp_err_str = _compile_err_str();
        print "OSaft::error_handler->new: internal error: unknown error type in \"$tmp_err_str\"." if ($err_hash{trace});
        carp ("OSaft::error_handler->new: internal error: unknown error type in \"$tmp_err_str\".");
        $err_hash{type} = OERR_UNKNOWN_TYPE;                    # overwrite error type to 'unknown', which is the most fatal
    } else {
        # undefined $arg_ref: no new error
        unless (defined ($arg_ref)) {
            $arg_ref->{type}    = OERR_UNKNOWN_TYPE;            # define error type to 'unknown', which is the most fatal
            $arg_ref->{module}  = 'OSaft::error_handler';
            $arg_ref->{sub}     = 'new';
            $arg_ref->{message} = "internal error: undefined \$arg_ref";
            $tmp_err_str        = _compile_err_str($arg_ref);
            print "$tmp_err_str" if ($err_hash{trace});
            carp ($tmp_err_str);
            return 0;
        }
        # undefined/unknown Error Type in new $arg_ref->{type}
        unless ( (exists ($ERROR_TYPE_RHASH_REF->{$arg_ref->{type}})) && (defined ($ERROR_TYPE_RHASH_REF->{$arg_ref->{type}})) ) {
            $tmp_err_str = _compile_err_str($arg_ref);
            print "OSaft::error_handler->new: internal error: unknown new error type in \"$tmp_err_str\"." if ($err_hash{trace});
            carp ("OSaft::error_handler->new: internal error: unknown new error type in \"$tmp_err_str\".");
            $arg_ref->{type} = OERR_UNKNOWN_TYPE;               # define error type to 'unknown', which is the most fatal
        }
        if ($arg_ref->{type} > $err_hash{type}) {               # New Error is less important than the previous
             my $old_err_str =  _compile_err_str();
             $tmp_err_str =     _compile_err_str($arg_ref);
             print ("OSaft::error_handler->new: new error type in \"$tmp_err_str\" is less important than the previous \"$old_err_str\".") if ($err_hash{trace});
             carp ("OSaft::error_handler->new: new error type in \"$tmp_err_str\" is less important than the previous \"$old_err_str\".");
             return 0;
        }
    }
    %err_hash = (
        %err_hash,                                              # previous keys and values
        %$arg_ref                                               # keys and values overwrite the previous
    ) if ($arg_ref);

    my $err_str = _compile_err_str();
    print "$err_str\n" if ($err_hash{print});
    carp ($err_str)    if ($err_hash{warn});
    return 1;
}


#?---------------------------------------------------------------------------------------
#? reset the error_handler (no error)
#? opionally owerwrite it with the hash values referenced by arg_ref
sub reset_err {
    my ($class, $arg_ref) = @_;                                 # $class is not used
    %err_hash = (                                               # reset to default values and overwrite by optional hash arg_ref
        type      => OERR_NO_ERROR,
        module    => "",
        sub       => OERR_UNKNOWN_TXT,
        id        => "",
        message   => OERR_UNKNOWN_TXT,
        print     => 0,
        warn      => 0,
        trace     => 1,
    );
    %err_hash = (
        %err_hash,                                              # previous keys and values
        %$arg_ref                                               # keys and values overwrite the previous if $arg_ref is defined and not empty
    ) if ($arg_ref);

    if ($err_hash{trace}>2) {
        my $err_str = _compile_err_str();
        print "$err_str\n";
    }
    return 1;
}


#?---------------------------------------------------------------------------------------
#? sub is_err():
#? returns true (1) if an error is stored in the hash of the error_handler
sub is_err {
    if ( (exists ($err_hash{type})) && (defined ($err_hash{type})) ) {
        return ($err_hash{type} != OERR_NO_ERROR);
    } else { # internal error: no type defined
       my $err_str = "OSaft::error_handler->is_err: internal error: undefined error type in \$error_hash: ";
       $err_str .= _compile_err_str();
       print "$err_str\n" if ($err_hash{trace}>2);
       carp ($err_str);
       return (1);
   }
}


#?---------------------------------------------------------------------------------------
#? sub get_err_type():
#? get error type (number)
sub get_err_type {
    if ( (exists ($err_hash {type})) && (defined ($err_hash {type})) ) {
        return ($err_hash {type});
    } else {
        print "Error type is ".OERR_UNDEFINED_TXT if ($err_hash{trace});
        carp ("Error type is ".OERR_UNDEFINED_TXT);
    }
    return (undef);
}


#?---------------------------------------------------------------------------------------
#? sub get_err_type_name():
#? get error type ame
sub get_err_type_name {
    if ( (exists ($err_hash {type})) && (defined ($err_hash {type})) ) {
        return ($ERROR_TYPE_RHASH_REF->{$err_hash{type}}) if ( (exists ($ERROR_TYPE_RHASH_REF->{$err_hash{type}})) && (defined ($ERROR_TYPE_RHASH_REF->{$err_hash{type}})) );
        return (OERR_UNKNOWN_TXT);
    } else {
        print "Error type is ".OERR_UNDEFINED_TXT if ($err_hash{trace});
        carp ("Error type is ".OERR_UNDEFINED_TXT);
    }
    return (OERR_UNDEFINED_TXT);
}


#?---------------------------------------------------------------------------------------
#? sub get_err_val():
#? get a single value of an error hash element
#? variables:
#? $class:              is automatically added when method is called
#? $key_arg:            hash key where the value sould be fetched
sub get_err_val {
    my ($class, $key_arg) = @_;                                 # $class is not used
    return ($err_hash {$key_arg}) if ( (exists ($err_hash {$key_arg})) && (defined ($err_hash {$key_arg})) );
    return;
}


#?---------------------------------------------------------------------------------------
#? sub get_err_str():
#? get the error string
#? no input variable needed
sub get_err_str {
    unless ( (exists ($ERROR_TYPE_RHASH_REF->{$err_hash{type}})) && (defined ($ERROR_TYPE_RHASH_REF->{$err_hash{type}})) ) { # undefined Error Type
        my $tmp_err_str = _compile_err_str();
        print ("OSaft::error_handler->get_err_str: internal error: unknown error type in \"$tmp_err_str\".\n") if ($err_hash{trace});
        carp ("OSaft::error_handler->get_err_str: internal error: unknown error type in \"$tmp_err_str\".\n");
        $err_hash{type} = OERR_UNKNOWN_TYPE;                    # overwrite error type to unknown, which is the most fatal
    }
    return (_compile_err_str());
}


#?---------------------------------------------------------------------------------------
#? sub get_err_hash ($;$$):
#? get the error hash as string (mainly used for debugging)
#? variables:
#? $class: added automaticially if called with 'error_handler->get_err_hash'
#? $prefix after a new line (e.g. some spaces for the indent)
#? $hash_ref: optional ref to an error_hash (default: %err_hash)
#? returns the compiled output
sub get_err_hash {
    my ($class, $prefix, $hash_ref) = @_;                       # $class is not used later, it is added automatically when calling the method
    my $err_hash_str                = "";
    $prefix =   ""         if (!defined($prefix));              # default is no indent
    $hash_ref = \%err_hash if (!defined($hash_ref));            # default is the error_hash
    print ">get_err_hash\n" if ($err_hash{trace}>2);
    #_trace "\n\$class =   $class\n";
    #_trace "\$hash_ref = ".\%$err_hash."\n";
    foreach my $err_key (sort (keys(%$hash_ref)) ) {
        $err_hash_str .= $prefix if ($err_hash_str !~ /^$/);    # not the first line
        $err_hash_str .= "\$hash->\{$err_key\} => ".$hash_ref->{$err_key}."\n";
    }
    return ($err_hash_str);
}


#?---------------------------------------------------------------------------------------
#? sub get_all_err_types($;$)
#? get all possible defined error types and their internal representation as a string (mainly used for debugging)
#? variable:
#? $class:      is added automatically when this method is used
#? $prefix:     optional prefix after new line (e.g. some spaces for the ident)
sub get_all_err_types {
    my ($class, $prefix) = @_;
    my $err_types_str="";
    print ">get_all_err_types\n" if ($err_hash{trace});
    foreach my $key (sort {$a <=> $b} (keys(%$ERROR_TYPE_RHASH_REF)) ) {
        $err_types_str .= $prefix if ($err_types_str !~ /^$/);  # not the first line
        $err_types_str .= "ERROR_TYPE_RHASH_REF\{$key\} => ".$ERROR_TYPE_RHASH_REF->{$key}."\n";
    }
    return ($err_types_str);
}

1;
