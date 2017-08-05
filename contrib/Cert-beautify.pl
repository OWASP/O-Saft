#!/usr/bin/perl -a -n -F:
#?
#? NAME
#?      Cert-beautify.pl    - formatting o-saft.pl's certificate data
#?
#? SYNOPSIS
#?      o-saft.pl +info ... | Cert-beautify.pl
#?      o-saft.pl +info ... | perl Cert-beautify.pl
#?      o-saft.pl +info -tracekey ... | Cert-beautify.pl
#?
#? DESCRIPTION
#?      Formats certificate related data for better human readability.
#?
#? VERSION
#?      @(#) Cert-beautify.pl 1.1 17/08/05 16:29:07
#?
#? AUTHOR
#?      07. August 2017 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

## no critic qw(Variables::ProhibitPackageVars)
#  NOTE: need "our" here because of autosplit mode (see -a -n)

use strict;
use warnings;

our %subject;
our %issuer;
our %finger;
our %dates;
my  $c = "Certificate";

sub printline {
	my ($key, $val) = @_;
	$val =~ s/^\s*//;
	printf("    %-24s%s", $key, $val);
	return;
} # printline

sub printvalue {
	my $line = shift;  # example: L=Mountain View
	return if ($line =~ m/^\s*$/);
	chomp $line;
	my $key  = "";
	my $val  = $line;
	$val =~ s/^[^=]*=//;
	$key = "Common Name (CN)"   if ($line =~ m/CN=/);
	$key = "Organisation (O)"   if ($line =~ m/O=/);
	$key = "Location (L)"       if ($line =~ m/L=/);
	$key = "State (ST)"         if ($line =~ m/ST=/);
	$key = "Country (C)"        if ($line =~ m/C=/);
	printline($key, "$val\n");
	return;
} # printvalue

/^\s*$/ and next;
/^=/    and next;
# NOTE: some : at end of string to distinguish from other matching strings
$subject{"Subject"}             = $F[-1] if m/^(#\[subject\]|$c Subject:)/;
$subject{"Issuer"}              = $F[-1] if m/^(#\[issuer\]|$c Issuer:)/;
$dates{"Valid from"}            = $F[-1] if m/^(#\[before\]|$c valid since:)/;
$dates{"Valid until"}           = $F[-1] if m/^(#\[after\]|$c valid until:)/;
$dates{"Certificate Chain"}     = $F[-1] if m/^(#\[verify\]|Validity $c Chain:)/;
$finger{"Serial Number"}        = $F[-1] if m/^(#\[serial\]|$c Serial Number)/;
$finger{"Subject Altnames"}     = $F[-1] if m/^(#\[altname\]|$c Subject's Alternate)/;
$finger{"Signature Algorithm"}  = $F[-1] if m/^(#\[signame\]|$c Signature Algorithm)/;
$finger{"Fingerprint"}          = $F[-1] if m/^(#\[fingerprint\]|$c Fingerprint:)/;
$finger{"Signature Value"}      = $F[-1] if m/^(#\[sigkey_len\]|$c Signature key Length)/;
$finger{"Public Key"}           = $F[-1] if m/^(#\[modulus_len\]|$c Public Key Length)/;
$finger{"Public Key Algorithm"} = $F[-1] if m/^(#\[pubkey_algorithm\]|$c Public Key Algorithm)/;
$finger{"Public Key Exponent"}  = $F[-1] if m/^(#\[modulus_exponent\]|$c Public Key Exponent)/;

END {
	local $\ = "\n";
	# FIXME: following split fails, is wrong if / is inside double quotes
	print  "\nIssued for (Subject)";
	# example: /C=US/ST=California/L=Mountain View/O=Google Inc/CN=*.google.de
	foreach my $key (split(m(/), $subject{"Subject"})) { printvalue($key); }
	print  "\nIssued from (Issuer)";
	# example: /C=US/ST=California/L=Mountain View/O=Google Inc/CN=*.google.de
	foreach my $key (split(m(/), $subject{"Issuer"}))  { printvalue($key); }
	print  "\nValidity";
	foreach my $key (keys %dates)   { printline($key, $dates{$key}); }
	print  "\nFingerprint";
	foreach my $key (sort keys %finger)  { printline($key, $finger{$key}); }
	print  "\nSignatures";
} # END
