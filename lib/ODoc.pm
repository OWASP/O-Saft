#!/usr/bin/perl -CADSio
## PACKAGE {

#!# Copyright (c) 2025, Achim Hoffmann
#!# This software is licensed under GPLv2.  Please see o-saft.pl for details.

package ODoc;
use strict;
use warnings;
use utf8;

# for description of "no critic" pragmas, please see  t/.perlcriticrc  and
# SEE Perl:perlcritic

## no critic qw(RegularExpressions::RequireExtendedFormatting)

#_____________________________________________________________________________
#___________________________________________________ package initialisation __|

my  $SID_odoc   = "@(#) ODoc.pm 3.39 25/01/10 17:13:03";
our $VERSION    = "24.09.24";   # official verion number of this file

BEGIN { # mainly required for testing ...
    # SEE Perl:@INC
    # SEE Perl:BEGIN perlcritic
    my $_path = $0;     $_path =~ s#[/\\][^/\\]*$##x;
    if (exists $ENV{'PWD'} and not (grep{/^$ENV{'PWD'}$/} @INC) ) {
        unshift(@INC, $ENV{'PWD'});
    }
    unshift(@INC, $_path)   if not (grep{/^$_path$/} @INC);
    unshift(@INC, "lib")    if not (grep{/^lib$/}    @INC);
}

use OText       qw(%STR);
use OCfg        qw(_dbx);

#_____________________________________________________________________________
#_____________________________________________________ public documentation __|

=pod

=encoding utf8


=head1 NAME

ODoc - Perl module to read O-Saft data for user documentation


=head1 DESCRIPTION

Utility package for O-Saft (o-saft.pl and related tools) to provide methods
which return user documentation from text files in various formats.


=head1 SYNOPSIS

=over 2

=item use ODoc;             # from within perl code

=item ODoc.pm --usage       # on command-line prints short usage

=item ODoc.pm [COMMANDS] F  # on command-line prints text of specified file

=back


=head1 METHODS

=head3 get($file)

Return all data from file as is, no conversions.
Returns data as array of lines.

=head3 get_custom($file,$name,$version)

Return all data from file replacing '$0' by $name and '$VERSION' by $version.
Returns data as array of lines.

=head3 get_markup($file,$name,$version)

Return all data converted to internal markup format.
Replaces '$0' by $name and '$VERSION' by $version.
Returns array of lines.

=head3 get_section($file,$start)

Return data for section starting at $start until next section from file.
Replace POD format by plain text. Returns data as string.

=head3 list

Print list of *.txt files in current directory. These files may be used for
following commands.


=head1 COMMANDS

If called from command-line, like:

  ODoc.pm COMMAND filename

this modules provides each method listed above as COMMAND.
Additionally following commands are available:

=over 4

=item VERSION

Print VERSION version.

=item version

Print internal version.

=back


=head1 OPTIONS

=over 4

=item --help

Print this help.

=item --usage

Print brief usage.

=back


=head1 MARKUP

Following notations / markups are used for public (user) documentation (for
example help.txt):

=over 2

=item TITLE

Titles start at beginning of a line, i.g. all upper case characters.

=item SUB-Title

Sub-titles start at beginning of a line prepended by 4 or 6 spaces.

=item code

Code lines start at beginning of a line prepended by 14 or more spaces.

=item "text in double quotes"

References to text or cite.

=item 'text in single quotes'

References to verbatim text elsewhere or constant string in description.

It is difficult to markup character classes like  a-zA-Z-  this way (using
quotes), because any character may be part of the class, including quotes or
those used for markup. For Example will  a-zA-Z-  look like  C<a-zA-Z->  in
POD format. Hence character classes are defined literally without markup to
avoid confusion.  However, when generating documentation it is assumed that
strings (words) beginning with  a-zA-Z  are character classes.

=item '*' list item (SEE Note:POD ERRORS)

Force list item (first level) in generated markup.

=item ** list item

Force list item (second level) in generated markup.

=item d) list item

Force list item in generated markup (d may be a digit or character).

=item $VERSION

Will be replaced by current version string (as defined in caller).

=item $0

Will be replaced by caller's name (i.g. o-saft.pl).

=item `$0'

Will not be replaced, but kept as is.

=back

Referenses to titles are written in all upper case characters  and prefixed
with 2 spaces and suffixed with 2 spaces or a . (dot) or , (comma).

There is only one special markup used:

=over 2

=item X&Some title here&

Referenses to sub-titles. It must be used to properly markup internal links
to sub-sections if the title is not written in all upper case.

=back

All head lines for sections (see TITLE above)  must be prepended by 2 empty
lines. A head line describing commands or options  should contain just this
command or option. Aliases for them should be written in their own line (to
avoid confusion in some other parsers, like Tcl).

List items should be followed by an empty line.

Texts in head lines for a section should not contain any quote characters.

I.g. no other markup is used in head lines.

Even lines starting with  '#' as first character are usually not treated as
comment line but verbatim text.

=head2 Special markups

=head3 Left hand space

=over 6

=item none        - head line level 1

=item exactly 4   - head line level 2

=item exactly 6   - head line level 3

=item exactly 11  - list item

=item exactly 14  - code line

=back

=head3 Left hand *:

=over 6

=item spaces *    - list item level 1

=item spaces **   - list item level 2

=back

=head3 Left hand digit or letter followed by )

List item may start with letter or digit followed by ) .

=head3 Special markups for o-saft.tcl

The sub-titles in the COMMANDS and OPTIONS sections must look like:

=over 6

=item Commands for whatever text

=item Commands to whatever text

=item Options for whatever text

=back

Means that the prefixes  "Commands for",  "Commands to"  and  "Options for"
are used to identify groups of commands and options. If a sub-title doesn't
start with these prefixes, all following commands and options are ignored.

=cut

#_____________________________________________________________________________
#_________________________________________________________ internal methods __|

sub _replace_var    {
    #? replace $0 by name and $VERSION by version in array, return array
    my ($name, $version, @arr) = @_;
    # SEE Perl:map()
    s#\$VERSION#$version#g  for @arr;   # add current VERSION
    s#(?<!`)\$0#$name#g     for @arr;   # my name
    return @arr;
} # _replace_var

sub _get_standalone {
    #? return help.txt with path in stand-alone mode
    # o-saft-standalone.pl may be in installtion path or in usr/ directory
    # hence various places for help.txt are checked
    my $file = shift;               # doc/help.txt
    my $name = $file;
       $name =~ s#(.*[/\\]+)##g;    # help.txt
    my $path = __FILE__;
       $path =~ s#/[^/\\]*$##;
    foreach my $f ("$file",   "$path/$file",      "$path/$name",
                      "$path/$OCfg::cfg{'dirs'}->{'doc'}/$name",
                      "$path/$OCfg::cfg{'dirs'}->{'lib'}/$name",
                      "$path/$OCfg::cfg{'dirs'}->{'lib'}/$file",
                      "$path/../$OCfg::cfg{'dirs'}->{'lib'}/$file"
                     ) {
        return $f if -e $f;
    }
    OCfg::warn("189: no '$file' found, consider installing");
    return "";
} # _get_standalone
if (1==42) { my $dumm = _get_standalone("never called, but keeps Perl::Critic happy"); }
    # avoids pragma 'no critic', hopefully other checkers won't complain too

sub _get_filehandle {
    #? return open file handle for passed filename,
    #? return Perl's DATA file handle of this file if file does not exist
    # passed file is searched for as is, in  .  and finally  doc/
    # this function is a wrapper for Perl's DATA
    # NOTE: finding the file in  .  may leed to corrupted, inappropriate file,
    #       for example after: ./o-saft.pl --help>help.txt
    #       see https://github.com/OWASP/O-Saft/issues/157
    my $file = shift || "";
    my $fh; # same as *FH
    local $\ = "\n";
    #dbx# print "#_get_filehandle: $0, file=$file, ",__FILE__;
    if ("" ne $file) {
        # file may be in same directory as caller, or in same as this module
        if (not -e $file) {
            my  $path = __FILE__;
                $path =~ s#^/($OCfg::cfg{'dirs'}->{'lib'}/.*)#$1#;# own module directory
                $path =~ s#/[^/\\]*$##;     # relative path of this file
                # Dirty hack: some OS return an absolute path for  __FILE__ ;
                # then $file would not be found because that path is wrong. If
                # the path begins with /OSaft the leading / is simply removed.
                # NOTE: This behaviour (on older Mac OSX) is considered a bug
                #       in Perl there.
            if (not -e "$path/$file") {
                $path =  $OCfg::cfg{'dirs'}->{'doc'}; # doc directory
            }
            $file = "$path/$file";
            # following line for gen_standalone.sh (used with make)
            # OSAFT_STANDALONE $file =  _get_standalone($file);
        }
    }
    #dbx# print "#_get_filehandle: file=$file ";
    #dbx# _trace("_get_filehandle: file=$file");
    if ("" ne $file and -e $file) {
        ## no critic qw(InputOutput::RequireBriefOpen)
        #  file hadnle needs to be closd by caller
        if (not open($fh, '<:encoding(UTF-8)', $file)) {
            OCfg::warn("190: open('$file'): $!");
        }
    } else { # FIXME: needs to be tested
        $fh = __PACKAGE__ . "::DATA";   # same as:  *ODoc::DATA
        OCfg::warn("191: no '$file' found, using '$fh'") if not -e $file;
    }
    #dbx# print "#_get_filehandle: file=$file , FH=*$fh";
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

sub get         { my $fh = _get_filehandle(shift); return <$fh>; }
    #? return data from file as string, no conversions
# TODO: misses  close($fh);

sub get_custom  {
    #? return data from file as string, replace $0 by $name and $VERSION by $version
    my $file    = shift;
    my $name    = shift || "o-saft.pl";
    my $version = shift || $VERSION;
    my @txt;
    my $fh      = _get_filehandle($file);
    return "" if ("" eq $fh);           # defensive programming
    for (<$fh>) {   ## no critic qw(InputOutput::ProhibitReadlineInForLoop)
        next if (m/^#begin/..m/^#end/); # remove egg
        next if (/^#/);                 # remove comments
        next if (/^\s*#.*#$/);          # remove formatting lines
        # special markup for tools, tool name ending with (1), ... (3pm)
        s/ {1,2}((?:Net::SSLeay|ldd|openssl|timeout|IO::Socket(?:::SSL|::INET)?)\(\d(?:pm)?\))/ "$1"/g; ## no critic qw(RegularExpressions::ProhibitComplexRegexes)
        # special markup for own tools
        ##s#([a-zA-Z0-9.,;:/] )(o-saft(?:\.(?:pl|tcl)?)|lib/[^./]*\.pm)#$1 "$2"#g;
        s/[IX]&([^&]*)&/$1/g;       # internal links without markup
        #s/L&([^&]*)&/"$1"/g;        # external links, must be last one
        push(@txt, $_);
    }
    return _replace_var($name, $version, @txt);
    # TODO: misses  close($fh);
} # get_custom

sub get_markup  {
    #? return data with internal markup, returns array of lines
    my $file    = shift;
    my $parent  = shift || "o-saft.pl";
    my $version = shift || $VERSION;
    my @txt;
    my $fh      = _get_filehandle($file);
    return "" if ("" eq $fh);           # defensive programming
    # Preformat plain text with markup for further simple substitutions. We
    # use a modified  &  instead of < >  POD markup as it is easy to parse.
    # &  was choosen because it rarely appears in texts and  is not  a meta
    # character in any of the supported  output formats (text, wiki, html),
    # and also causes no problems inside regex.
    for (<$fh>) {   ## no critic qw(InputOutput::ProhibitReadlineInForLoop)
                    #  There is no differnce if the array is allocated by
                    #  using a local variable or implecitely in the loop
        ## no critic qw(RegularExpressions::ProhibitComplexRegexes)
            # it's the nature of some regex to be complex
        # SEE MARKUP
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
        s/^( {18})([^ ].*)/S&$1$2&/;    # exactly 18
        # check for other markup in lines which are not code examples or
        # already injected other markup;
        # SEE Note:Markup for Tool Examples;  SEE Note:Markup for Internal Links
        # quick&dirty: identifying code examples by
        #     $0 o-saft o-saft.tcl o-saft-docker checkAllCiphers.pl perl perlapp perl2exe
        # quick&dirty: should also not match  X& ... & as no other potential
        # markup should be substituted in there
        if (not m/^(?:=|S&|\s+(?:\$0|o-saft|o-saft.tcl|o-saft-docker|checkAllCiphers.pl|perl|perl2exe|perlapp)\s)/
            and not m/X&[^&]*(?:\+|--)/
           ) {  # more markup, ...
            s#(\s)+(a-zA-Z[^ ]+)(\s+)#$1'$2'$3#g;   # markup literal character class as code
            # our commands and options; SEE Note:Markup for Commands and Options
            s#(\s)((?:\+|--)[^,\s).]+)([,\s).])#$1I&$2&$3#g;
                # TODO: fails for something like:  --opt=foo="bar"
                # TODO: above substitute fails for something like:  --opt --opt
                #        hence same substitute again (should be sufficent then)
            s#([A-Z]L)&#$1 &#g;         # SEE Note:Upercase Markup
################ --option=,   extra behandeln
                # quick&dirty to avoid further inerpretation of L& , i.e. SSL
                # ugly hack as it adds a space
            s#(\s)((?:\+|--)[^,\s).]+)([,\s).])#$1I&$2&$3#g;
        }
        if (not m/^S/ and not m/^ {14,}/) {
            # special markup for tools, tool name ending with (1), ... (3pm)
            s/((?:Net::SSLeay|ldd|openssl|timeout|IO::Socket(?:::SSL|::INET)?)\(\d(?:pm)?\))/L&$1&/g;
            # special markup for own tools
            ##s#([a-zA-Z0-9.,;:/] )(o-saft(?:\.(?:pl|tcl)?)|lib/[^./]*\.pm)#$1 "$2"#g;
        }
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
            s/ (SHELL TWEAKS)/ X&$1&/g;
            s/ (SEE ALSO)/ X&$1&/g;
            s/ (EXIT STATUS)/ X&$1&/g;
            s/ (CIPHER NAMES)/ X&$1&/g;
            s/ (LAZY SYNOPSIS)/ X&$1&/g;
            s/ (KNOWN PROBLEMS)/ X&$1&/g;
            s/ (BUILD DOCKER IMAGE)/ X&$1&/g;
            s/ (BUILD DOCKER IMAGE)/ X&$1&/g;
            s/ (TECHNICAL INFORMATION)/ X&$1&/g;
            s/ (NAME|CONCEPTS|ENVIRONMENT)/ X&$1&/g;
            s/ (COMMANDS|OPTIONS|RESULTS|CHECKS|OUTPUT|CUSTOMISATION) / X&$1& /g;
            s/ (LIMITATIONS|DEPENDENCIES|INSTALLATION|DOCKER|TESTING) / X&$1& /g;
            s/ (SCORING|EXAMPLES|ATTRIBUTION|DOCUMENTATION|VERSION) / X&$1& /g;
            s/ (DESCRIPTION|SYNOPSIS|QUICKSTART|SECURITY|DEBUG|AUTHOR) / X&$1& /g;
        }
        push(@txt, $_);
    }
    close($fh);
    return _replace_var($parent, $version, @txt);
} # get_markup

sub get_section {
    #? return data of section $start from file as string, removes POD format
    my $file    = shift;
    my $label   = lc(shift) || "";  # || to avoid "Use of uninitialised value"
    my $anf     = uc($label);
    my $end     = "[A-Z]";
    my $hlp;
#   _dbx("get_section($anf, $end) ...");
    # no special help, print full one or parts of it
    my $fh  = _get_filehandle($file);
    my $txt = join ("", <$fh>); ## no critic qw(InputOutput::ProhibitJoinedReadline)
    close($fh);
    if ($label =~ m/^name/i)    { $end = "TODO";  }
    $txt =~ s/.*?\n$anf/$anf/ms;
    $txt =~ s/\n$end.*//ms;             # grep all data
        # $txt contains now anthing between $anf and $end     
    # remove markup
    $txt =~ s/\n#[^\n]*//g;
    $txt =~ s/[IX]&([^&]*)&/$1/g;       # internal links without markup
    if (0 < (grep{/^--v/} @ARGV)) {     # do not use $^O but our own option
        # some systems are tooo stupid to print strings > 32k, i.e. cmd.exe
        OCfg::warn("192: using workaround to print large strings.\n\n");
        $hlp .= $_ foreach split(//, $txt);  # print character by character :-((
    } else {
        $hlp .= $txt;
    }
    return $hlp;
} # get_section

sub get_section_from_pod {
    #? return data of section $start from file as string, removes POD format
    my $file    = shift;
    my $label   = lc(shift) || "";  # || to avoid "Use of uninitialised value"
    my $anf     = uc($label);
    my $end     = "[A-Z]";
    my $hlp;
#   _dbx("get_section_from_pod($anf, $end) ...");
    # no special help, print full one or parts of it
    my $txt = join("", get_markup($file));
    if ($label =~ m/^name/i)    { $end = "TODO";  }
    #$txt =~ s{.*?(=head. $anf.*?)\n=head. $end.*}{$1}ms;# grep all data
        # above terrible performance and unreliable, hence in peaces below
    $txt =~ s/.*?\n=head1 $anf//ms;
    $txt =~ s/\n=head1 $end.*//ms;      # grep all data
        # $txt contains now anthing between and including $anf and $end     
    # remove markup
    $txt = "\n=head1 $anf" . $txt;
    $txt =~ s/\n=head2 ([^\n]*)/\n    $1/msg;
    $txt =~ s/\n=head3 ([^\n]*)/\n      $1/msg;
    $txt =~ s/\n=(?:[^ ]+ (?:\* )?)([^\n]*)/\n$1/msg;# remove inserted markup
    $txt =~ s/\nS&([^&]*)&/\n$1/g;
    $txt =~ s/[IX]&([^&]*)&/$1/g;       # internal links without markup
    $txt =~ s/L&([^&]*)&/"$1"/g;        # external links, must be last one
    if (0 < (grep{/^--v/} @ARGV)) {     # do not use $^O but our own option
        # some systems are tooo stupid to print strings > 32k, i.e. cmd.exe
        OCfg::warn("192: using workaround to print large strings.\n\n");
        $hlp .= $_ foreach split(//, $txt);  # print character by character :-((
    } else {
        $hlp .= $txt;
    }
    return $hlp;
} # get_section_from_pod

sub list    {
    #? return sorted list of available .txt files in ./doc or doc/ directory
    #  sorted list simplifies tests ...
    my $dir = shift;
       $dir =~ s#[/\\][^/\\]*$##;
       $dir .= "/$OCfg::cfg{'dirs'}->{'doc'}" if $dir !~ m#$OCfg::cfg{'dirs'}->{'doc'}/?$#;
       $dir  =   $OCfg::cfg{'dirs'}->{'doc'}  if not -d $dir; # last resort
    my @txt;
    opendir(my $dh, $dir) or return $!;
    while (my $file = readdir($dh)) {
        next unless (-f "$dir/$file");
        next unless ($file =~ m/\.txt$/);
        push(@txt, $file);
    }
    closedir($dh);
    return join("\n", sort @txt);
} # list

#_____________________________________________________________________________
#____________________________________________________ internal test methods __|

# none, piblic methods used directly

#_____________________________________________________________________________
#___________________________________________________ initialisation methods __|

# none

#_____________________________________________________________________________
#_____________________________________________________________________ main __|

sub _main   {
    #? print own documentation or that from specified file
    my @argv = @_;
    push(@argv, "--help") if (0 > $#argv);
    my %usage = (
      '# internal commands' => {
          'list'        =>'list available files',
      },
      '# commands to get text from file in various formats(examples)' => {
          'get help.txt'        =>'show own SID',
          'get-custom help.txt' =>'show text with some variables replaced',
          'get-markup help.txt' =>'show text with internal makup',
          'get-section help.txt SECTION'=>'show specified section from file',
      },
    );
    # got arguments, do something special
    while (my $cmd = shift @argv) {
        OText::print_pod($0, __PACKAGE__, $SID_odoc) if ($cmd =~ m/^--?h(?:elp)?$/x);
        OText::usage_show("", \%usage) if ($cmd eq '--usage');
        my $arg    = shift @argv;   # get 2nd argument, which is filename
        my $sec    = "NAME";        # used for get_section only
           $sec    = shift @argv || "NAME" if ($cmd =~ /^get.?section/);
        # ----------------------------- commands
        #_usage()                if ($cmd eq '--usage');
        print list($0) . "\n"   if ($cmd =~ /^list$/);
        print get($arg)         if ($cmd =~ /^get$/);
        print get_custom($arg)  if ($cmd =~ /^get.?custom$/);
        print get_markup($arg)  if ($cmd =~ /^get.?mark(?:up)?/);
        print get_section($arg, $sec) if ($cmd =~ /^get.?section/);
        print "$SID_odoc\n"     if ($cmd =~ /^version$/);
        print "$VERSION\n"      if ($cmd =~ /^[-+]?V(?:ERSION)?$/);
    }
    exit 0;
} # _main

sub done    {}; # dummy to check successful include

#_____________________________________________________________________________
#_____________________________________________________ public documentation __|

=pod

=head1 SEE ALSO

lib/OText.pm


=head1 VERSION

3.39 2025/01/10


=head1 AUTHOR

17-oct-17 Achim Hoffmann

=cut

## PACKAGE }

#_____________________________________________________________________________
#_____________________________________________________________________ self __|

_main(@ARGV) if (not defined caller);

1;

# __END__
    # __end__ not possible, because we may get
    # readline() on unopened filehandle DATA at ODoc.pm line 184.

# SEE Note:Documentation
# All public (user) documentation is in plain ASCII format (see help.txt).

=pod

=head1 Annotations, Internal Notes

The annotations here are for internal documentation only.
For details about our annotations, please SEE  Annotations,  in o-saft.pl.


=head3 Documentation:General

All public user documentation is written in plain text format. Hence it is
possible to read it without a special tool. It is designed for human read-
ability and simple editing.

All other formats like HTML, POD, troff (man-page), etc. will be generated
from this plain text with the methods (functions) herein.
The general workflow is as follows:

=over

=item 1. read text file

=item 2. inject simple, intermediate markup (i.g. dokuwiki style markup)

=item 3. convert intermediate markup to required format

=back

For generating some formats, external tools are used.  Such a tools mainly
gets the data in POD format and then converts it to another format. 
The external tools are called using Perl's 'exec()' function, usually.

=head2 Note:Upercase Markup

There's a conflict in detecting TITLEs and options with uppercase letters,
for example  --SSL  .  To avoid incorrectly mixed markup,  the sequence of
some pattern matching is important.

=head2 Note:Markup for Internal Links

In some cases it is not possible to identify targets for internal links in
the human readable text, because such targets are also human readable text
but not written in all uppercase letters.
Therefore the special markup  X&some text here&  can be used.

No other pattern must be matched in this markup.

=head2 Note:Markup for Commands and Options

While commands are easy to detect, it may become complicated for options.
The general pattern for options is: starting with  --  and all charachters
before next space, comma, or dot.

Unfortunately options may contain such terminating characters too. Special
handling for such options must be implemented,  otherwise generated markup
may not behave as intended.

=head2 Note:Markup for Tool Examples

The documentation contains example code to call tools.  It is obvious that
the examples also conatain texts looking like our own options. The options
shouldn't be subject to special markup of option, like generating internal
links (HTML).

A list of tools (pattern) is used to detect such code examples. Such lines
are identified if the first word in the line matches this paatern.

=head2 Note:POD ERRORS

POD's =item keyword doesn't allow that following text starts with a * . It
then complains with something like:

  POD ERRORS
  Around line 522:
      Expected text after =item, not a bullet

That's why '*' (star enclosed in single quotes) is used instead of * .

=cut

__DATA__
