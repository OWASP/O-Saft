#! /usr/bin/perl -w -I . -I ..
#?
#? NAME
#?      $0 - einfaches Testscript für Methoden von Net::SSLinfo
#?
#? SYNOPSIS
#?      $0 [host] [port]
#?
#?      Default:  mail.google.com 443
#?

use strict;
use warnings;

if (0 <= $#ARGV) {
	if ($ARGV[0] =~ m/^--?h(?:elp)?$/) {
		# quick&dirty
		system("sed -ne 's#\$0#$0#g' -e '/^#?/s/#?//p' $0");
		exit 0;
	}
}

my $SID  = "@(#) %M% %I% %E% %U%";
my $VERSION = 'dumm';

use Net::SSLinfo; # qw(open_ssl);

my $host = $ARGV[0] || 'mail.google.com'; # ssllabs.com
my $port = $ARGV[1] || 443;

#my ($ssl, $ctx) = 
	#do_ssl_open($host, $port);

print "# $host:$port ...\n";
my $pem = PEM($host,$port); # hier werden die Daten besorgt, danach ist $host, $port nicht mehr nötig
my @err = errors($host,$port);
if (0 <= $#err) {
	push(@err, "\n# alle folgenden Werte sind evtl. zufällig oder falsch!");
}
print join("\n",
	'===============',
	"errors:\n" . join("\n", @err),
	'===============',
	"PEM:\n" . $pem,
	'===============',
	"text:\n" . text(),
	'===============',
	"Validity:\n"       . join(" .. ", dates()),
	"Not valid before:" . before(),
	"Not valid after: " . after(),
	'===============',
	"Subject Name:    " . subject(),
	"Issuer  Name:    " . issuer(),
	"Serial Number:   " . serial(),
	"Serial Number I: " . serial_int(),
	"Serial Number H: " . serial_hex(),
	'===============',
	"Default Cipher:  " . selected(),
#	"Cipher List:     " . ciphers(),
	'',
	"Fingerprint:     " . fingerprint(),
	"Fingerprint hash:" . fingerprint_hash(),
	"Fingerprint SHA1:" . fingerprint_sha1(),
	"Fingerprint SHA2:" . fingerprint_sha2(),
	"Fingerprint MD5: " . fingerprint_md5(),
	#'===============',
	#Net::SSLeay::get_peer_certificate(),
	#Net::SSLeay::dump_peer_certificate(),
	'',
	);

print
	"===============\n",
	"Authority:       " . authority($host, $port),
	"\n",
	"Alt Names:       " . altname($host, $port),  # bei 'v.gy' gibt es eines
	"\n",
	"Verify Hostname: " . verify_hostname($host, $port),  # bei 'alix' passt es nicht
	"\n",
	"Verify Alt Name: " . verify_alias($host, $port),  # bei 'ssllabs.com' 
	"\n";

do_ssl_close($host, $port);

exit;

