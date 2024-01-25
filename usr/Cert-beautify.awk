#!/usr/bin/gawk -f
#?
#? NAME
#?      Cert-beautify.awk   - formatting o-saft.pl's certificate data
#?
#? SYNOPSIS
#?      o-saft.pl +info ... | Cert-beautify.awk
#?      o-saft.pl +info ... | gawk -f Cert-beautify.awk
#?      o-saft.pl +info ... | Cert-beautify.awk -v all=1
#?
#? OPTIONS
#?      -v all=1    - prints all line not matching certificate data from input
#?                    default is to extract matching certificate data only
#?
#? DESCRIPTION
#?      Formats certificate related data for better human readability.
#?
#? VERSION
#?      @(#) Cert-beautify.awk 1.2 17/07/15 00:52:43
#?
#? AUTHOR
#?      07. July 2017 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

function write(key,val) {
	sub(/^[ \t]*/, "", val);
	printf"    %-22s%s\n", key, val;
}
BEGIN	{ FS = ":"; }

/^\s*$/	{ if (all==0) {next} }
/^=/	{ if (all==0) {next} }
# line with --tracekey
/^#\[subject\]/		{ data["Subject"]           = $3; next; }
/^#\[issuer\]/		{ data["Issuer"]            = $3; next; }
/^#\[before\]/		{ dates["Valid from"]       = $3; next; }
/^#\[after\]/		{ dates["Valid until"]      = $3; next; }
/^#\[serial\]/		{ finger["Serial Number"]   = $3; next; }
/^#\[altname\]/		{ finger["Subject Altnames"]= $3; next; }
/^#\[signame\]/		{ finger["Signature Algorithm"] = $3; next; }
/^#\[fingerprint\]/	{ finger["Fingerprint"]     = $3; next; }
/^#\[sigkey_len\]/	{ finger["Signature Value"] = $3; next; }
/^#\[modulus_len\]/	{ finger["Public Key"]      = $3; next; }
/^#\[pubkey_algorithm\]/{ finger["Public Key Algorithm"] = $3; next; }
/^#\[modulus_exponent\]/{ finger["Public Key Exponent"]  = $3; next; }
/^#\[verify\]/		{ $1=""; $2=""; finger["Certificate Chain"] = $0; next; }
# line without --tracekey
/^Certificate Subject's Alternate:/	{ finger["Subject Altnames"]= $2; next; }
/^Certificate Subject:/			{ data["Subject"]           = $2; next; }
/^Certificate Issuer:/			{ data["Issuer"]            = $2; next; }
/^Certificate valid since:/		{ dates["Valid from"]       = $2; next; }
/^Certificate valid until:/		{ dates["Valid until"]      = $2; next; }
/^Certificate Serial Number:/		{ finger["Serial Number"]   = $2; next; }
/^Certificate Signature Algorithm:/	{ finger["Signature Algorithm"] = $2; next; }
/^Certificate Fingerprint:/		{ finger["Fingerprint"]     = $2; next; }
/^Certificate Signature Key Length:/	{ finger["Signature Value"] = $2; next; }
/^Certificate Public Key Length:/	{ finger["Public Key"]      = $2; next; }
/^Certificate Public Key Algorithm:/	{ finger["Public Key Algorithm"] = $2; next; }
/^Certificate Public Key Exponent::/	{ finger["Public Key Exponent"]  = $2; next; }
/^Validity Certificate Chain:/		{ $1=""; dates["Certificate Chain"] = $0; next; }
{ if (all==1) {print} }

END	{
	split(data["Subject"], arr, "/");
	#asort(arr);
	for (key in arr) {
		val = arr[key];
		#printf"  %-14s%s\n", key, val;
		if (val ~ /CN=/) { subjct["Common Name (CN)"] = substr(val, 4); }
		if (val ~ /O=/)  { subjct["Organisation (O)"] = substr(val, 3); }
		if (val ~ /L=/)  { subjct["Location (L)"]     = substr(val, 3); }
		if (val ~ /ST=/) { subjct["State (ST)"]       = substr(val, 4); }
		if (val ~ /C=/)  { subjct["Country (C)"]      = substr(val, 3); }
	}
	split(data["Issuer"], arr, "/");
	for (key in arr) {
		val = arr[key];
		#printf"  %-14s%s\n", key, val;
		if (val ~ /CN=/) { issuer["Common Name (CN)"] = substr(val, 4); }
		if (val ~ /O=/)  { issuer["Organisation (O)"] = substr(val, 3); }
		if (val ~ /L=/)  { issuer["Location (L)"]     = substr(val, 3); }
		if (val ~ /ST=/) { issuer["State (ST)"]       = substr(val, 4); }
		if (val ~ /C=/)  { issuer["Country (C)"]      = substr(val, 3); }
	}
	print "\nIssued for (Subject)";
	for (key in subjct) { write(key, subjct[key]); }
	print "\nIssued from (Issuer)";
	for (key in issuer) { write(key, issuer[key]); }
	print "\nValidity";
	for (key in dates)  { write(key, dates[key]);  }
	print "\nFingerprints and Signatures";
	for (key in finger) { write(key, finger[key]); }
	print "";
}

# __DATA__
# Example:
#
#[cn]:              Certificate Common Name:            demo
#[subject]:         Certificate Subject:                /C=US/ST=California/L=Mountain View/O=Google Inc/CN=*.google.de
#[subject_hash]:    Certificate Subject Name Hash:      f6e9b9c5
#[issuer]:          Certificate Issuer:                 /C=US/O=Google Inc/CN=Google Internet Authority G2
#[issuer_hash]:     Certificate Issuer Name Hash:       f6e9b9c5
#[serial]:          Certificate Serial Number:          13434941386788252546 (0xba72800289b52b82)
#[fingerprint]:     Certificate Fingerprint:            SHA1 Fingerprint=55D7A8009A0FB2B2467716A8F209FF7F6AA8C95B
#[fingerprint_type]:Certificate Fingerprint Algorithm:  SHA1
#[fingerprint_hash]:Certificate Fingerprint Hash Value: 55D7A8009A0FB2B2467716A8F209FF7F6AA8C95B
#[fingerprint_sha2]:Certificate Fingerprint SHA2:       143EDA5B172589299D45126A054DEC858F5375B0D6490F7FB5F2D30A81571D3A
#[fingerprint_sha1]:Certificate Fingerprint SHA1:       55D7A8009A0FB2B2467716A8F209FF7F6AA8C95B
#[fingerprint_md5]: Certificate Fingerprint  MD5:       3A879291D4616D8762EF0F847230DC2F
#[before]:          Certificate valid since:            Feb 11 10:29:01 2016 GMT
#[after]:           Certificate valid until:            Feb 16 10:29:01 2016 GMT
#[signame]:         Certificate Signature Algorithm:    sha256WithRSAEncryption
#[sigkey_len]:      Certificate Signature Key Length:   2048
#[pubkey_algorithm]:Certificate Public Key Algorithm:   rsaEncryption
#[modulus_len]:     Certificate Public Key Length:      2048
#[modulus_exponent]:Certificate Public Key Exponent:    65537 (0x10001)
#[aux]:             Certificate Trust Information:      
#[trustout]:        Certificate trusted:                	
#[altname]:         Certificate Subject's Alternate Names:
