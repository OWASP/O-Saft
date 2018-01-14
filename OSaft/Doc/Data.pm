#!/usr/bin/perl
## PACKAGE {

#!# Copyright (c) Achim Hoffmann, sic[!]sec GmbH
#!# This software is licensed under GPLv2.  Please see o-saft.pl for details.

## no critic qw(Documentation::RequirePodSections)
#        Our POD below is fine, Perl::Critic (severity 2) is too pedantic here.

## no critic qw(RegularExpressions::ProhibitFixedStringMatches)
#        Using regex instead of strings is not bad.  Perl::Critic (severity 2)
#        is too pedantic here.

## no critic qw(ControlStructures::ProhibitPostfixControls)
#        We believe it's better readable (severity 2 only)

package OSaft::Doc::Data;

use strict;
use warnings;

my  $VERSION    = "18.01.18";  # official verion number of tis file
my  $SID        = "@(#) Data.pm 1.4 18/01/14 22:30:08";

# binmode(...); # inherited from parent, SEE Perl:binmode()

#_____________________________________________________________________________
#_____________________________________________________ public documentation __|

=pod

=encoding utf8

=head1 NAME

OSaft::Doc::Data - common Perl module to read data for user documentation

=head1 SYNOPSIS

    use OSaft::Doc::Data;

=head1 METHODS

=cut

#_____________________________________________________________________________
#_________________________________________________________ internal methods __|

sub _replace_var {
    #? replace $0 by name and $VERSION by version in array, return array
    my ($name, $version, @arr) = @_;
    # SEE Perl:map()
    s#\$VERSION#$version# for @arr;     # add current VERSION
    s# \$0# $name#        for @arr;     # my name
    return @arr;
} # _replace_var

sub _get_filehandle {
    #? return open file handle for passed filename,
    #? return Perl's DATA file handle if file does not exist
    # this function is a wrapper for Perl's DATA
    my $file = shift || "";
    my $fh; # same as *FH
    local $\ = "\n";
    if ($file ne "") {
        # file may be in same directory as caller, or in same as this module
        if (not -e $file) {
            my  $path = __FILE__;
                $path =~ s#/[^/\\]*$##; # relative path of this file
            $file = "$path/$file";
            #dbx# print "file: $file";
        }
    }
    if ($file ne "" and -e $file) {
        ## no critic qw(InputOutput::RequireBriefOpen)
        #  file hadnle needs to be closd by caller
        if (not open($fh, '<:encoding(UTF-8)', $file)) {
            print "**WARNING: open('$file'): $!";
        }
    } else {
        $fh = __PACKAGE__ . "::DATA";   # same as:  *OSaft::Doc::Data::DATA
        print "**WARNING: no '$file' found, using '$fh'" if not -e $file;
    }
    #dbx# print "file: $file , FH: *$fh";
    return $fh;
} # _get_filehandle

#_____________________________________________________________________________
#__________________________________________________________________ methods __|

sub get_egg     {
    #? get easter egg from text
    my $fh      = _get_filehandle(shift);
    my $egg     = "";   # set empty to avoid "Use of uninitialized value" later
    while (<$fh>) { $egg .= $_ if (m/^#begin/..m/^#end/); }
    $egg =~ s/#(begin|end) .*\n//g;
    close($fh);
    return scalar reverse "\n$egg";
} # get_egg

=pod

=head2 get_markup($file,$name,$version)

Return all data converted to internal markup format. Returns array of lines.

=cut

sub get_markup    {
    my $file    = shift;
    my $parent  = shift || "o-saft.pl";
    my $version = shift || $VERSION;
    my @txt;
    my $fh      = _get_filehandle($file);
    # Preformat plain text with markup for further simple substitutions. We
    # use a modified (& instead of < >) POD markup as it is easy to parse.
    # &  was choosen because it rarely appears in texts and  is not  a meta
    # character in any of the supported  output formats (text, wiki, html),
    # and also causes no problems inside regex.
    for (<$fh>) {   ## no critic qw(InputOutput::ProhibitReadlineInForLoop)
                    #  There is no differnce if the array is allocated by
                    #  using a local variable or implecitely in the loop
        ## no critic qw(RegularExpressions::ProhibitComplexRegexes)
            # it's the nature of some regex to be complex
        next if (m/^#begin/..m/^#end/); # remove egg
        next if (/^#/);                 # remove comments
        next if (/^\s*#.*#$/);          # remove formatting lines
        s/^([A-Z].*)/=head1 $1/;
        s/^ {4}([^ ].*)/=head2 $1/;
        s/^ {6}([^ ].*)/=head3 $1/;
        # for =item keep spaces as they are needed in man_help()
        s/^( +[a-z0-9]+\).*)/=item * $1/;# list item, starts with letter or digit and )
        s/^( +\*\* .*)/=item $1/;       # list item, second level
        s/^( +\* .*)/=item $1/;         # list item, first level
        s/^( {11})([^ ].*)/=item * $1$2/;# list item
        s/^( {14})([^ ].*)/S&$1$2&/;    # exactly 14 spaces used to highlight line
        if (!m/^(?:=|S&|\s+\$0)/) {     # no markup in example lines and already marked lines
            s#(\s)((?:\+|--)[^,\s).]+)([,\s).])#$1I&$2&$3#g; # markup commands and options
                # TODO: fails for something like:  --opt=foo="bar"
                # TODO: above substitute fails for something like:  --opt --opt
                #        hence same substitute again (should be sufficent then)
            s#(\s)((?:\+|--)[^,\s).]+)([,\s).])#$1I&$2&$3#g;
        }
        s/((?:Net::SSLeay|ldd|openssl|timeout|IO::Socket(?:::SSL|::INET)?)\(\d\))/L&$1&/g;
        s/((?:Net::SSL(?:hello|info)|o-saft(?:-dbx|-man|-usr|-README)(?:\.pm)?))/L&$1&/g;
        s/  (L&[^&]*&)/ $1/g;
        s/(L&[^&]*&)  /$1 /g;
            # If external references are enclosed in double spaces, we squeeze
            # leading and trailing spaces 'cause additional characters will be
            # added later (i.e. in man_help()). Just pretty printing ...
        if (m/^ /) {
            # add internal links; quick&dirty list here
            # we only want to catch header lines, hence all capital letters
            s/ ((?:DEBUG|RC|USER)-FILE)/ X&$1&/g;
            s/ (CONFIGURATION (?:FILE|OPTIONS))/ X&$1&/g;
            s/ (COMMANDS|OPTIONS|RESULTS|CHECKS|OUTPUT|INSTALLATION) / X&$1& /g;
            s/ (CUSTOMIZATION|SCORING|LIMITATIONS|DEBUG|EXAMPLES) / X&$1& /g;
        }
        push(@txt, $_);
    }
    close($fh);
    return _replace_var($parent, $version, @txt);
} # get_markup

=pod

=head2 get_text($file)

Same as  get()  but with some variables substituted.

=cut

sub get_text    {
    #? print program's help
# NOTE: NOT YET READY, not yet used
    my $file    = shift;
    my $label   = shift || "";  # || to avoid uninitialized value
       $label   = lc($label);
    my $anf     = uc($label);
    my $end     = "[A-Z]";
#   _man_dbx("man_help($anf, $end) ...");
    # no special help, print full one or parts of it
    my $txt = join ("", get_markup($file));
#   #if ((grep{/^--v/} @ARGV) > 1) {     # with --v --v
#   #    print scalar reverse "\n\n$egg";
#   #    return;
#   #}
#print "T $txt T";
    if ($label =~ m/^name/i)    { $end = "TODO";  }
    #$txt =~ s{.*?(=head. $anf.*?)\n=head. $end.*}{$1}ms;# grep all data
        # above terrible performance and unreliable, hence in peaces below
    $txt =~ s/.*?\n=head1 $anf//ms;
    $txt =~ s/\n=head1 $end.*//ms;      # grep all data
    $txt = "\n=head1 $anf" . $txt;
    $txt =~ s/\n=head2 ([^\n]*)/\n    $1/msg;
    $txt =~ s/\n=head3 ([^\n]*)/\n      $1/msg;
    $txt =~ s/\n=(?:[^ ]+ (?:\* )?)([^\n]*)/\n$1/msg;# remove inserted markup
    $txt =~ s/\nS&([^&]*)&/\n$1/g;
    $txt =~ s/[IX]&([^&]*)&/$1/g;       # internal links without markup
    $txt =~ s/L&([^&]*)&/"$1"/g;        # external links, must be last one
    if ((grep{/^--v/} @ARGV) > 0) {     # do not use $^O but our own option
        # some systems are tooo stupid to print strings > 32k, i.e. cmd.exe
        print "**WARNING: using workaround to print large strings.\n\n";
        print foreach split(//, $txt);  # print character by character :-((
    } else {
        #print $txt;
    }
#print "t $txt t";
    if ($label =~ m/^todo/i)    {
        print "\n  NOT YET IMPLEMENTED\n";
# TODO: {
#        foreach my $label (sort keys %checks) {
#            next if (_is_member($label, \@{$cfg{'commands-NOTYET'}}) <= 0);
#            print "        $label\t- " . $checks{$label}->{txt} . "\n";
#        }
# TODO: }
    }
    return $txt;
} # get_text

=pod

=head2 get_as_text($file)

Return all data from file as is. Returns data as string.

=cut

sub get_as_text { my $fh = _get_filehandle(shift); return <$fh>; }
# TODO: misses  close($fh);

=pod

=head2 get($file,$name,$version)

Return all data from file and replace $0 by $name. Returns data as string.

=cut

sub get         {
    my $file    = shift;
    my $name    = shift || "o-saft.pl";
    my $version = shift || $VERSION;
    my $fh      = _get_filehandle($file);
    return _replace_var($name, $version, <$fh>);
    # TODO: misses  close($fh);
} # get

=pod

=head2 print_ast_text($file)

Same as  get()  but prints text directly.

=cut

sub print_as_text { my $fh = _get_filehandle(shift); print  <$fh>; return; }
# TODO: misses  close($fh);

sub _main_help  {
    #? print help
    printf("# %s %s\n", __PACKAGE__, $VERSION);
    if (eval {require POD::Perldoc;}) {
        # pod2usage( -verbose => 1 );
        exit( Pod::Perldoc->run(args=>[$0]) );
    }
    if (qx(perldoc -V)) {
        # may return:  You need to install the perl-doc package to use this program.
        #exec "perldoc $0"; # scary ...
        printf("# no POD::Perldoc installed, please try:\n  perldoc $0\n");
        exit 0;
    }
}; # _main_help

=pod

=head1 COMMANDS

If called from command line, like

  OSaft/Doc/Data.pm [COMMANDS] file

this modules provides following commands:

=head2 VERSION

Print VERSION version.

=head2 version

Print internal version.

=head2 list

Print list of *.txt files in current directory.

=head2 get filename

Call get(filename).

=head2 get_text(filename

Call get_text(filename).

=head2 get_markup filename

Call get_text(filename).

=head2 print_as_text filename

Call print_as_text(filename).

=head1 OPTIONS

=over 4

=item --V

Print VERSION version.

=back

=cut

sub list        {
    my $dir = $0;
       $dir =~ s#[/\\][^/\\]*$##;
    my $txt =  "";
    opendir(DIR, $dir) or return $!;
    while (my $file = readdir(DIR)) {
        next unless (-f "$dir/$file");
        next unless ($file =~ m/\.txt$/);
        $txt .= "$file\n";
    }
    closedir(DIR);
    return $txt;
} # list

sub _main       {
    #? print own documentation
    ## no critic qw(InputOutput::RequireEncodingWithUTF8Layer)
    #   see .perlcritic for detailed description of "no critic"
    binmode(STDOUT, ":unix:utf8"); # latin1 geht nicht
    binmode(STDERR, ":unix:utf8");

    if ($#ARGV < 0) { _main_help; exit 0; }

    # got arguments, do something special
    while (my $cmd = shift @ARGV) {
        my $arg = shift @ARGV;
        if ($cmd =~ /^--?h(?:elp)?$/  ) { _main_help; exit 0;     }
        # ----------------------------- commands
        if ($cmd =~ /^list$/)           { print list();           }
        if ($cmd =~ /^get$/)            { print get($arg);        }
        if ($cmd =~ /^get.?mark(up)?/)  { print get_markup($arg); }
        if ($cmd =~ /^get.?text/)       { print get_text($arg);   }
        if ($cmd =~ /^print$/)          { print_as_text($arg);    }
        if ($cmd =~ /^version$/)        { print "$SID\n"; exit 0; }
        if ($cmd =~ /^(-+)?V(ERSION)?$/){ print "$VERSION\n"; exit 0; }
    }
    exit 0;
} # _main

sub o_saft_help_done   {};      # dummy to check successful include

=pod

=head1 SEE ALSO

# ...

=head1 VERSION

$(VERSION)
C<$VERSION>

=head1 AUTHOR

17-oct-17 Achim Hoffmann

=cut

## PACKAGE }

#_____________________________________________________________________________
#_____________________________________________________________________ self __|

_main() if (! defined caller);

1;

# SEE Note:Documentation
# All documentation is in plain ASCII format.
# It's designed for human radability and simple editing.
#
# Following notations / markups are used:
#   TITLE
#       Titles start at beginning of a line, i.g. all upper case characters.
#     SUB-Title
#       Sub-titles start at beginning of a line preceeded by 4 or 6 spaces.
#     code
#       Code lines start at beginning of a line preceeded by 14 or more spaces.
#   "text in double quotes"
#       References to text or cite.
#   'text in single quotes'
#       References to verbatim text elswhere or constant string in description.
#   * list item
#       Force list item (first level) in generated markup.
#   ** list item
#       Force list item (second level) in generated markup.
#   d) list item
#       Force list item in generated markup (d may be a digit or character).
#   $VERSION
#       Will be replaced by current version string (as defined in caller).
#   $0
#       Will be replaced by caller's name (i.g. o-saft.pl).
#
#   Referenzes to titles are written in all upper case characters and prefixed
#   and suffixed with 2 spaces.
#
#   There is only one special markup used:
#   X&Some title here&
#       which refers to sub-titles, it must be used to properly markup internal
#       links to sub-sections if the title is not written in all upper case.
#
#   All head lines for sections (see TITLE above) are preceeded by 2 empty lines.
#   All head lines for commands and options should contain just this command
#   or option, aliases should be written in their own line (to avoid confusion
#   in some other parsers, like Tcl).
#   List items should be followed by an empty line.
#   Texts in section headers should not contain any quote characters.
#   I.g. no other markup is used. Even Lines starting with # as first character
#   are usually not treated as comment line but verbatim text.
#
# Special markups for o-saft.tcl:
#   - the sub-titles in the COMMANDS and OPTIONS sections must look like:
#       Commands for whatever text
#       Commands to whatever text
#       Options for whatever text
#     means that the prefixes  "Commands for"  and  "Options for"  are used to
#     identify groups of commands and options. If a sub-title does not start
#     with these prefixes, all following commands and options are ignored.

__DATA__

