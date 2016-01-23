#!/usr/bin/perl -w
#?
#? NAME
#?      $0 - postprocess to colourize output of o-saft.pl
#?
#? SYNOPSIS
#?      o-saft.pl | $0 [OPTIONS]
#?
#? DESCRIPTION
#?      That's it.
#?
#? OPTIONS
#?      --h     got it
#?      --test  simple self-testing
#?      --line  colourize complete line
#?      --word  colourize special words
#?      --italic colourize special words and additionally print "label texts:"
#?               with italic characters
#?              "label text:" is all text left of first : including :
#?      --NUM   if a number, change assumed terminal width to NUM
#?              (used for padding text on the right);  default: terminal width
#?
#? LIMITATIONS
#
# HACKER's INFO
#       Feel free to write your own code. You just need to add/modify the code
#       following "main" below.
#
#       How it workd, see function  testeme  below calling with  $0 --test
#?
#? VERSION
#?      @(#) bunt.pl 1.2 16/01/21 23:08:47
#?
#? AUTHOR
#?      08-jan-16 Achim Hoffmann _at_ sicsec .dot. de
#?
# -----------------------------------------------------------------------------

$::ich   = $0; $::ich =~ s#.*[/\\]##;
sub _warn($) { print STDERR "[$::ich]: **", @_, "\n"; }

if (defined $ENV{TERM}) {
	_warn("WARNING: TERM=screen; take care ...") if ($ENV{TERM} eq 'screen');
} # else
	# not a terminal, switch off terminal capabilities
	# checks are done with:    (defined $ENV{TERM})
	# probably better exit here

# --------------------------------------------- internal variables; defaults
my $mode    = 'word';   # default: colourize words
my $italic  = 0;        # default: nothing italic
my $_LEN    = 80;       # default: 80 characters per line; set to termial width below
my $cols = $_LEN;

# check terminal width

if ($^O =~ m/MSWin32/) {
	my $rows;
	$cols = $ENV{COLUMNS};
	if (eval { require Win32::Console; }) {
		($cols, $rows) = Win32::Console::Size();
	} else {
	  if (eval { require Term::Size; }) {
		($cols, $rows) = Term::Size::chars *STDOUT{IO};
		#($x, $y) = Term::Size::pixels;
	  } # else ... gave up; feel free to try harder on dumb system
	}
	if (! defined $cols) {
		_warn("WARNING: cannot find terminal width, using default $_LEN");
		_warn("HINT: consider setting COLUMNS environment variable");
		$cols = $_LEN;
	}
} else { $cols = qx(\\tput cols); } # quick&dirty
chomp $cols;
if (defined $ENV{COLUMNS}) {
	_warn("WARNING: terminal width $ENV{COLUMNS} mismatch, using $cols") if ($ENV{COLUMNS} ne $cols);
	$_LEN = $cols;
}
$_LEN = $cols;

%::map = (
	# colours  # escape sequence to be used
	#----------+----------------------------------------
	'black'  => '0;30m',    'dark_gray'    => '1;30m',
	'red'    => '0;31m',    'light_red'    => '1;31m',
	'green'  => '0;32m',    'light_green'  => '1;32m',
	'brown'  => '0;33m',    'yellow'       => '1;33m',
	'blue'   => '0;34m',    'light_blue'   => '1;34m',
	'purple' => '0;35m',    'light_purple' => '1;35m',
	'cyan'   => '0;36m',    'light_cyan'   => '1;36m',
	'gray'   => '0;37m',    'white'        => '1;37m',
	'off'    => '0m',   # used to reset colours
	''       => '',  # dummy
	#----------+----------------------------------------
);

# --------------------------------------------- functions
sub colour ($$$) {
	my ($fg, $bg, $txt) = @_;
	return $txt if (!defined $ENV{TERM});
	$bg = $::map{$bg};
	$fg = $::map{$fg};
	$bg =~ s#;3#;4#    if ($bg ne "");
	$bg = "\033[${bg}" if ($bg ne "");
	$fg = "\033[${fg}" if ($fg ne "");
	return "$fg$bg$txt\033[0m";
}
sub colour_reset () { print colour('off', '', ''); }

sub deco ($$) {
	my ($mm, $txt) = @_;
	return $txt if (!defined $ENV{TERM});
	return "\033[$mm$txt\033[0m";
}
sub bold ($)      { return deco('1m', shift); }
sub dim ($)       { return deco('2m', shift); }
sub italic ($)    { return deco('3m', shift); }
sub underline ($) { return deco('4m', shift); }
sub reversebg ($) { return deco('7m', shift); }
sub reversefg ($) { return deco('8m', shift); }
sub strike ($)    { return deco('9m', shift); }

# as changing text colour (forground) is the most common usage, there is one
# function for each color, and one function to just switch the background

sub black ($)     { return colour('black',  "", shift); }
sub red ($)       { return colour('red',    "", shift); }
sub green ($)     { return colour('green',  "", shift); }
sub brown ($)     { return colour('brown',  "", shift); }
sub blue ($)      { return colour('blue',   "", shift); }
sub purple ($)    { return colour('purple', "", shift); }
sub magenta ($)   { return colour('purple', "", shift); } # alias for purple
sub cyan ($)      { return colour('cyan',   "", shift); }
sub gray ($)      { return colour('gray',   "", shift); }
sub white ($)     { return colour('white',  "", shift); }
sub yellow ($)    { return colour('yellow', "", shift); }
sub boldred ($)   { return colour('light_red',    "", shift); }
sub boldpurple ($){ return colour('light_purple', "", shift); }
sub something ($) { return colour('purple', "", shift); }
sub background ($){ return colour("",       shift, ""); }

sub italic_label ($) {
	my $txt = shift;
	$txt =~ s/^(.*:)(.*)/return italic($1),$2;/es;
	return $txt;
}

sub pad_right ($) {
	my $txt = shift;
	my $_t  = "";
	$_t .= " " for length($txt)..($_LEN - 1);
	return "$txt$_t";
}

sub testeme () {
	my ($txt, $and, $t2, $t3);
	$txt = pad_right "  line padded"; print reversebg "$txt\n";
	$and = reversebg "and";
	print red     " line  red\n";
	print green   " line  green\n";
	print brown   " line  brown\n";
	print blue    " line  blue\n";
	print purple  " line  purple\n";
	print cyan    " line  cyan\n";
	print gray    " line  gray\n";
	print black   " line  black\n";
	print white   " line  white\n";
	print yellow  " line  yellow\n";
	print underline " line  underlined\n";
	print strike  " line  striked\n";
	print bold    " line  bold\n";
	print italic  " line  italic\n";
	print something " line  something\n";
		$txt = red    "red";
		$t2  = green  "green";
		$t3  = underline "underlined";
	print " line with $txt word\n";
	print " line with $txt $and $t2 $and $t3 word\n";
		$txt = bold   "bold";
		$t2  = dim    "dimmed";
		$t3  = strike "striked";
	print " line with $txt $and $t2 $and $t3 word\n";
		$txt = bold   "striked bold green";
		$txt = strike "$txt";
		$txt = green  "$txt";
	print " line with $txt word\n";
	print reversebg " line reverse\n";
	print italic_label "label with italic text:\t\tnormal text \n";
	background 'cyan';		# FIXME: does not yet work proper
	print colour('black', 'cyan', " line  black\n");
	print colour('green', 'cyan', " line  green\n");
	print " line\n";
	background 'off';
	print boldred " line bold red\n";
	colour_reset;    # no reset background completely;
	print green "done\n";
}

# --------------------------------------------- options
while ( $#ARGV >= 0 ) {
	my $arg = shift;
	if ($arg =~ m/--?h(elp)/) {
		open(FID, $0) || die "[$0]: **ERROR: cannot read myself.\n";
		grep { s/\$0/$::ich/g; /#\?(.*)$/ && print "$1\n"; } (<FID>);
		exit 0;
	}
	if ($arg =~ m/--version/) {
		open(FID, $0) || die "$0: WARNING: cannot read myself.\n";
		grep { /^#\?\s*@\(#\)/ && s/#\?// && print } (<FID>);
	}
	if ($arg =~ m/--line/)   { $mode='line'; $italic=0; }
	if ($arg =~ m/--word/)   { $mode='word'; }
	if ($arg =~ m/--italic/) { $mode='word'; $italic=1; }
	if ($arg =~ m/--test/)   { testeme; exit 0; }
	if ($arg =~ m/--(\d+)/)  {
		my $num = $1;
		_warn("WARNING: given width $num larger than computed size $_LEN") if ($num > $_LEN);
		$_LEN = $num
	}
}

# --------------------------------------------- main

# get o-saft.pl's markup as regex
#	o-saft.pl --help=ourstr

sub bgcyan ($) {
	background "cyan";
	print gray shift;
	colour_reset;    # FIXME: does not yet work proper
}

if (-t STDIN) {
	_warn("ERROR: text on STDIN expected; exit");
	exit 2;
}

while ($line = <STDIN>) {
	$_ = $line; # = $_;
	if ("$line" =~ m/^\s*$/) { print "\n"; next; } # speed!
	#{ all modes
	  /^\#\[/	&& last;
	  /^##yeast*CMD:/ && do {     bgcyan  "$line";   next; };
	  /^\#/		&& do { print blue    "$line";   next; };
	  /^\*\*HINT/	&& do { print purple  "$line";   next; };
	  /^\*\*WARN/	&& do { print boldpurple "$line";next; };
	  /^\*\*ERROR/	&& do { print boldred "$line";   next; };
	  /^=+/ && do {
		chomp $line;
		$txt = pad_right "$line"; print reversebg "$txt\n";
		next;
		};
	  /^Use of .*perl/ && do { print purple "$line"; next; };
	#} all modes

	if ($mode eq "line") {
		/<<[^>]*>>/	&& do {	print cyan  "$line"; next; };
		/yes.*WEAK/i	&& do {	print red   "$line"; next; };
		/yes.*LOW/i	&& do {	print red   "$line"; next; };
		/yes.*MEDIU/i	&& do {	print brown "$line"; next; };
		/yes.*HIGH/i	&& do {	print green "$line"; next; };
		/yes$/	&& do {	print green "$line"; next; };
		/no$/		&& do {	print brown "$line"; next; };
		/no .*/	&& do {	print red   "$line"; next; };
		print "$line"; next;
	}

	if ($mode eq "word") {
		/yes\s*(LOW|WEAK|MEDIUM|HIGH)$/i && do {
			s/(LOW)$/    red   $1;/ie;
			s/(WEAK)$/   red   $1;/ie;
			s/(MEDIUM)$/ brown $1;/ie;
			s/(HIGH)$/   green $1;/ie;
			print "$_";
			next;
		};
		s/^([^:]+:)/italic $1; /e if ($italic == 1);
		#/yes\s*$/	&& do { s/(yes)\s*$/   green  $1/ie; print "$_\n"; next; };
		s/(yes\s*$)/     green  $1/ie && print && next;
		s/(no\s*$)/      brown  $1/ie && print && next;
		s/(no\s+\(.*\))/ yellow $1/ie && print && next;
		s/(#\[[^\]]*])/  cyan   $1/ie && print && next;
		print;
        }

}

exit 0
