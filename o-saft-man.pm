#!/usr/bin/perl
## PACKAGE {

#!# Copyright (c) Achim Hoffmann, sic[!]sec GmbH
#!# This  software is licensed under GPLv2. Please see o-saft.pl for details.

package main;   # ensure that main:: variables are used

## no critic qw(ValuesAndExpressions::ProhibitCommaSeparatedStatements)
# FIXME: we have a lot of comman separated statements to simplify the code.
#        needs to be changed in future to keep perlcritic happy.
#        However, the code herein is just for our own documentation ...

## no critic qw(RegularExpressions::ProhibitCaptureWithoutTest)
# NOTE:  This often happens in comman separated statements, see above.
#        It may also happen after postfix statements.
#        Need to check regularily for this problem ...

## no critic qw(RegularExpressions::ProhibitComplexRegexes)
# NOTE:  Yes, we have very complex regex here.

## no critic qw(InputOutput::RequireBriefOpen)
#        we always close our filehandles, perlcritic is too stupid to read over 15 lines

## no critic qw(ValuesAndExpressions::ProhibitNoisyQuotes)
#        we have a lot of single character strings, herein, that's ok

use strict;
use warnings;
use vars qw(%checks %data %text); ## no critic qw(Variables::ProhibitPackageVars)
binmode(STDOUT, ":unix");
binmode(STDERR, ":unix");

use osaft;

my  $man_SID= "@(#) o-saft-man.pm 1.128 16/06/28 08:19:15";
my  $parent = (caller(0))[1] || "O-Saft";# filename of parent, O-Saft if no parent
    $parent =~ s:.*/::;
    $parent =~ s:\\:/:g;                # necessary for Windows only
my  $wer    = (caller(1))[1];           # tricky to get filename of myself when called from BEGIN
my  $ich    = $wer;
    $ich    = "o-saft-man.pm" if (! defined $ich); # sometimes it's empty :-((
    $ich    =~ s:.*/::;
    $wer    = $ich if -e $ich;          # check if exists, otherwise use what caller() provided
if (! defined $wer) {                   # still nothing found, try parent
    $wer    = (caller(0))[1];           # parent;
    if (! defined $wer) {
        $wer    = $0;                   # still nothing found, last resort: myself
    } else {
        $wer    =~ s#/[^/\\]*$##;       # path of parent
        $wer   .= "/$ich";              # append myself
    }
    print "**WARNING: no '$wer' found" if ! -e $wer;
}
my  $version= "$man_SID";               # version of myself
    $version= _VERSION() if (defined &_VERSION); # or parent's if available
my  $jump   = 1;
my  $egg    = "";
our @DATA;
my  $cfg_header = 0;                   # we may be called from within parents BEGIN, hence no %cfg available
    $cfg_header = 1 if ((grep{/^--header/} @ARGV)>0);
my  $file   = undef;
if (open($file, '<:encoding(UTF-8)', $wer)) {
    # If this module is used in parent's BEGIN{} section, we don't have any
    # file descriptor, in particular nothing beyond __DATA__. Hence we need
    # to read the file --this one-- manually, and strip off anything before
    # __DATA__. Stripping could be done using perl's  grep, join and splice
    # functions, but using a simple loop is more readable.
    # Preformat plain text with markup for further simple substitutions. We
    # use a modified (& instead of < >) POD markup as it is easy to parse.
    # &  was choosen because it rarely appears in texts and  is not  a meta
    # character in any of the supported  output formats (text, wiki, html),
    # and also causes no problems inside regex.
    while (<$file>) {
        $jump = 2, next if (/^#begin/);
        $jump = 0, next if (/^#end/);
        $jump = 0, next if (/^__DATA__/);
        $egg .= $_,next if ($jump == 2);
        next if ($jump != 0);
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
        s#\$VERSION#$version#g;         # add current VERSION
        s# \$0# $parent#g;              # my name
        push(@DATA, $_);
    }
    close($file);
}
local $\ = "";

#| definitions: more documentations as data
#| -------------------------------------
my %man_text = (
    # short list of used terms and acronyms, always incomplete ...
    'glossar' => {
        'AA'        => "Attribute Authority",
        'AAD'       => "additional authenticated data",
        'ACL'       => "Access Control List",
        'ADH'       => "Anonymous Diffie-Hellman",
        'Adler32'   => "hash function",
        'AEAD'      => "Authenticated Encryption with Additional Data",
        'AECDHE'    => "Anonymous Ephemeral ECDH",
        'AEM'       => "Authenticated Encryption Mode aka Advanced Encryption Mode aka OCB3",
        'AES'       => "Advanced Encryption Standard",
        'AIA'       => "Authority Information Access (certificate extension)",
        'AKC'       => "Agreement with Key Confirmation",
        'AKID'      => "Authority Key IDentifier",
        'ALPN'      => "Application Layer Protocol Negotiation",
        'ARC4'      => "Alleged RC4 (see RC4)",
        'ARCFOUR'   => "alias for ARC4",
        'ARIA'      => "128-bit Symmetric Block Cipher",
        'ASN'       => "Autonomous System Number",
        'ASN.1'     => "Abstract Syntax Notation number One",
        'BACPA'     => "Blockwise-adaptive chosen-plaintext attack",
        'BEAR'      => "block cipher combining stream cipher and hash function",
        'BDH'       => "Bilinear Diffie-Hellman",
        'BEAST'     => "Browser Exploit Against SSL/TLS",
        'BER'       => "Basic Encoding Rules",
        'BGP'       => "Boorder Gateway Protocol",
        'Blowfish'  => "symmetric block cipher",
        'BREACH'    => "Browser Reconnaissance & Exfiltration via Adaptive Compression of Hypertext (a variant of CRIME)",
                    #   http://www.breachattack.com/
        'Bullrun'   => "NSA program to break encrypted communication",
        'CAMELLIA'  => "Encryption algorithm 128 bit (by Mitsubishi and NTT)",
        'CAST-128'  => "Carlisle Adams and Stafford Tavares, block cipher",
        'CAST5'     => "alias for CAST-128",
        'CAST-256'  => "Carlisle Adams and Stafford Tavares, block cipher",
        'CAST6'     => "alias for CAST-256",
        'cipher suite'  => "cipher suite is a named combination of authentication, encryption, and message authentication code algorithms",
        'CA'        => "Certificate Authority (aka root CA)",
        'CAA'       => "Certificate Authority Authorization",
        'CAA RR'    => "CAA Resource Record",
        'CBC'       => "Cyclic Block Chaining",
        'CBC '      => "Cipher Block Chaining (sometimes)",
        'CBC  '     => "Ciplier Block Chaining (sometimes)",
        #   ^^-- spaces to make key unique
        'CBC-MAC'   => "Cipher Block Chaining - Message Authentication Code",
        'CBC-MAC-ELB'   => "Cipher Block Chaining - Message Authentication Code - Encrypt Last Block",
        'CCM'       => "CBC-MAC Mode",
        'CCS'       => "Change Cipher Spec (protocol)",
        'CDH'       => "?  Diffie-Hellman",
        'CDP'       => "CRL Distribution Points",
        'CEK'       => "Content Encryption Key",
        'CFB'       => "Cipher Feedback",
        'CFB3'      => "Cipher Feedback",
        'CFBx'      => "Cipher Feedback x bit mode",
        'CHAP'      => "Challenge Handshake Authentication Protocol",
        'CKA'       => "", # PKCS#11
        'CKK'       => "", # PKCS#11
        'CKM'       => "", # PKCS#11
        'CMAC'      => "Cipher-based MAC",
        'CMP'       => "X509 Certificate Management Protocol",
        'CMS'       => "Cryptographic Message Syntax",
        'CMVP'      => "Cryptographic Module Validation Program (NIST)",
        'CN'        => "Common Name",
        'CP'        => "Certificate Policy (certificate extension)",
        'CPD'       => "Certificate Policy Definitions",
        'CPS'       => "Certification Practice Statement",
        'CRC'       => "Cyclic Redundancy Check",
        'CRC8'      => "CRC with polynomial length 8",
        'CRC16'     => "CRC with polynomial length 16",
        'CRC32'     => "CRC with polynomial length 32",
        'CRC64'     => "CRC with polynomial length 64",
        'CRAM'      => "Challenge Response Authentication Mechanism",
        'CRIME'     => "Compression Ratio Info-leak Made Easy (Exploit SSL/TLS)",
        'CRL'       => "Certificate Revocation List",
        'CSP'       => "Certificate Service Provider",
        'CSP '      => "Cryptographic Service Provider",
        'CSP  '     => "Critical Security Parameter (used in FIPS 140-2)",
        'CSP:'      => "Content Security policy",     # used as HTTP header, hence the stranke key here
        'CSR'       => "Certificate Signing Request",
        'CT'        => "Certificate Transparency",
        'CTL'       => "Certificate Trust Line",
        'CTR'       => "Counter Mode (sometimes: CM; block cipher mode)",
        'CTS'       => "Cipher Text Stealing",
        'Curve25519'   => "signature algorithm by Dan J. Bernstein",
        'CWC'       => "CWC Mode (Carter-Wegman + CTR mode; block cipher mode)",
        'DAA'       => "Data Authentication Algorithm",
        'DAC'       => "Data Authentication Code",
        'DACL'      => "Discretionary Access Control List",
        'DANE'      => "DNS-based Authentication of Named Entities",
        'DDH'       => "Decisional Diffie-Hellman (Problem)",
        'DEA'       => "Data Encryption Algorithm (sometimes a synonym for DES)",
        'DECIPHER'  => "synonym for decryption",
        'DEK'       => "Data Encryption Key",
        'DER'       => "Distinguished Encoding Rules",
        'DES'       => "Data Encryption Standard",
        'DESede'    => "alias for 3DES ?java only?",
        'DESX'      => "extended DES",
        '3DES'      => "Tripple DES (168 bits)",
        '3DES-EDE'  => "alias for 3DES",
        '3TDEA'     => "Three-key  Tripple DEA (sometimes: Tripple DES; 168 bits)",
        '2TDEA'     => "Double-key Tripple DEA (sometimes: Double DES; 112 bits)",
        'D5'        => "Verhoeff's Dihedral Group D5 Check",
        'DH'        => "Diffie-Hellman",
        'DHE'       => "Diffie-Hellman ephemeral", # historic acronym, often used, mainly in openssl
        'DLIES'     => "Discrete Logarithm Integrated Encryption Scheme",
        'DLP'       => "Discrete Logarithm Problem",
        'DN'        => "Distinguished Name",
        'DNSSEC'    => "DNS Security Extension",
        'DPA'       => "Dynamic Passcode Authentication (see CAP)",
        'DRBG'      => "Deterministic Random Bit Generator",
        'DROWN'     => "Decrypting RSA with Obsolete and Weakened eNcryption (Exploit SSL/TLS)",
                    #  https://drownattack.com/
        'DSA'       => "Digital Signature Algorithm",
        'DSS'       => "Digital Signature Standard",
        'DTLS'      => "Datagram TLS",
        'DTLSv1'    => "Datagram TLS 1.0",
        'Dual EC DBRG'   => "Dual Elliptic Curve Deterministic Random Bit Generator",
        'DV'        => "Domain Validation",
        'DV-SSL'    => "Domain Validated Certificate",
        'EAL'       => "Evaluation Assurance Level",
        'EAP'       => "Extensible Authentication Protocol",
        'EAP-PSK'   => "Extensible Authentication Protocol using a Pre-Shared Key",
        'EAX'       => "EAX Mode (block cipher mode)",
        'EAXprime'  => "alias for EAX Mode",
        'EC'        => "Elliptic Curve",
        'ECB'       => "Electronic Code Book mode",
        'ECC'       => "Elliptic Curve Cryptography",
        'ECDH'      => "Elliptic Curve Diffie-Hellman",
        'ECDHE'     => "Ephemeral ECDH",
        'ECDSA'     => "Elliptic Curve Digital Signature Algorithm",
        'ECGDSA'    => "Elliptic Curve ??? DSA",
        'ECIES'     => "Elliptic Curve Integrated Encryption Scheme",
        'ECKA'      => "Elliptic Curve Key Agreement",
        'ECKA-EG'   => "Elliptic Curve Key Agreement of ElGamal Type",
        'ECKDSA'    => "Elliptic Curve ??? DSA",
        'ECMQV'     => "Elliptic Curve Menezes-Qu-Vanstone",
        'ECOH'      => "Elliptic Curve only hash",
#       'ECRYPT'    => " ?? ",
        'Ed25519'   => "alias for Curve25519",
        'EDE'       => "Encryption-Decryption-Encryption",
        'EDH'       => "Ephemeral Diffie-Hellman", # official acronym
        'EGADS'     => "Entropy Gathering and Distribution System",
        'EGD'       => "Entropy Gathering Daemon",
        'EKU'       => "Extended Key Usage",
        'ELB'       => "Encrypt Last Block",
        'ElGamal'   => "asymmetric block cipher",
        'ENCIPHER'  => "synonym for encryption",
        'EME'       => "Encoding Method for Encryption",
        'ESP'       => "Encapsulating Security Payload",
        'EtM'       => "Encrypt-then-MAC",
        'ETSI-TS'   => "European Telecommunications Standards Institute - Technical Specification",
        'EV'        => "Extended Validation",
        'EV-SSL'    => "Extended Validation Certificate",
        'FEAL'      => "Fast Data Encryption Algorithm",
        'FFC'       => "Finite Field Cryptography",
        'FIPS'      => "Federal Information Processing Standard",
        'FIPS46-2'  => "FIPS Data Encryption Standard (DES)",
        'FIPS73'    => "FIPS Guidelines for Security of Computer Applications",
        'FIPS140-2' => "FIPS Security Requirements for Cryptographic Modules",
        'FIPS140-3' => "proposed revision of FIPS 140-2",
        'FIPS180-3' => "FIPS Secure Hash Standard",
        'FIPS186-3' => "FIPS Digital Signature Standard (DSS)",
        'FIPS197'   => "FIPS Advanced Encryption Standard (AES)",
        'FIPS198-1' => "FIPS The Keyed-Hash Message Authentication Code (HMAC)",
        'FREAK'     => "Factoring Attack on RSA-EXPORT Keys",
        'FQDN'      => "Fully-qualified Domain Name",
        'FSB'       => "Fast Syndrome Based Hash",
        'FSM'       => "Finite State Machine",
        'FZA'       => "FORTEZZA",
        'G-DES'     => "??? DES",
        'GCM'       => "Galois/Counter Mode (block cipher mode)",
        'GHASH'     => "Hash funtion used in GCM",
        'GMAC'      => "MAC for GCM",
        'GOST'      => "Gossudarstwenny Standard (block cipher)",
        'Grainv1'   => "stream cipher (64-bit IV)",
        'Grainv128' => "stream cipher (96-bit IV)",
        'hash127'   => "fast hash function (by Dan Bernstein)",
        'HAVAL'     => "one-way hashing",
        'HAS-160'   => "hash function",
        'HAS-V'     => "hash function",
        'HC128'     => "stream cipher",
        'HC256'     => "stream cipher",
        'HEARTBLEED'=> "attack against TLS extension heartbeat",
        'HIBE'      => "hierarchical identity-based encryption",
        'HMAC'      => "keyed-Hash Message Authentication Code",
        'HMQV'      => "h? Menezes-Qu-Vanstone",
        'HSM'       => "Hardware Security Module",
        'HPKP'      => "HTTP Public Key Pinning",
        'HSTS'      => "HTTP Strict Transport Security",
        'HTOP'      => "HMAC-Based One-Time Password",
        'IAPM'      => "Integrity Aware Parallelizable Mode (block cipher mode of operation)",
        'ICM'       => "Integer Counter Mode (alias for CTR)",
        'IDEA'      => "International Data Encryption Algorithm (by James Massey and Xuejia Lai)",
        'IFC'       => "Integer Factorization Cryptography",
        'IGE'       => "Infinite Garble Extension",
        'IND-BACPA' => "Indistinguishability of encryptions under blockwise-adaptive chosen-plaintext attack",
        'IND-CCA'   => "Indistinguishability of encryptions under chosen-cipgertext attack",
        'IND-CPA'   => "Indistinguishability of encryptions under chosen-plaintext attack",
        'INT-CTXT'  => "Integrity of ciphertext",
        'INT-PTXT'  => "Integrity of plaintext",
        'ISAKMP'    => "Internet Security Association and Key Management Protocol",
        'IV'        => "Initialization Vector",
        'JSSE'      => "Java Secure Socket Extension",
        'KCI'       => "Key Compromise Impersonation",
        'KEA'       => "Key Exchange Algorithm (alias for FORTEZZA-KEA)",
        'KEK'       => "Key Encryption Key",
        'KSK'       => "Key Signing Key", # DNSSEC
        'LFSR'      => "Linear Feedback Shift Register",
        'LION'      => "block cipher combining stream cipher and hash function",
        'LM hash'   => "LAN Manager hash aka LanMan hash",
        'Logjam'    => "Attack to force server to downgrade to export ciphers",
        'LRA'       => "Local Registration Authority",
        'Lucky 13'  => "Break SSL/TLS Protocol",
        'MARS'      => "",
        'MAC'       => "Message Authentication Code",
        'MCF'       => "Modular Crypt Format",
        'MDC2'      => "Modification Detection Code 2 aka Meyer-Schilling",
        'MDC-2'     => "same as MDC2",
        'MD2'       => "Message Digest 2",
        'MD4'       => "Message Digest 4",
        'MD5'       => "Message Digest 5",
        'MEE'       => "MAC-then-Encode-then-Encrypt",
        'MEK'       => "Message Encryption Key",
        'MECAI'     => "Mutually Endorsing CA Infrastrukture",
        'MGF'       => "Mask Generation Function",
        'MISTY1'    => "block cipher algorithm",
        'MQV'       => "Menezes-Qu-Vanstone (authentecated key agreement",
        'MtE'       => "MAC-then-encrypt",
        'NCP'       => "Normalized Certification Policy (according TS 102 042)",
        'Neokeon'   => "symmetric block cipher algorithm",
        'nonce'     => "(arbitrary) number used only once",
        'NPN'       => "Next Protocol Negotiation",
        'NSS'       => "Network Security Services",
        'NTLM'      => "NT Lan Manager. Microsoft Windows challenge-response authentication method.",
        'NULL'      => "no encryption",
        'NUMS'      => "nothing up my sleeve numbers",
        'OAEP'      => "Optimal Asymmetric Encryption Padding",
        'OCB'       => "Offset Codebook Mode (block cipher mode of operation)",
        'OCB1'      => "same as OCB",
        'OCB2'      => "improved OCB aka AEM",
        'OCB3'      => "improved OCB2",
        'OCSP'      => "Online Certificate Status Protocol",
        'OCSP stapling' => "formerly known as: TLS Certificate Status Request",
        'OFB'       => "Output Feedback",
        'OFBx'      => "Output Feedback x bit mode",
        'OID'       => "Object Identifier",
        'OMAC'      => "One-Key CMAC, aka CBC-MAC",
        'OMAC1'     => "same as CMAC",
        'OMAC2'     => "same as OMAC",
        'OPIE'      => "One-time pad Password system",
        'OTP'       => "One Time Pad",
        'OV'        => "Organisational Validation",
        'OV-SSL'    => "Organisational Validated Certificate",
        'P12'       => "see PKCS#12",
        'P7B'       => "see PKCS#7",
        'PACE'      => "Password Authenticated Connection Establishment",
        'PAKE'      => "Password Authenticated Key Exchange",
        'PBE'       => "Password Based Encryption",
        'PBKDF2'    => "Password Based Key Derivation Function",
        'PC'        => "Policy Constraints (certificate extension)",
        'PCBC'      => "Propagating Cipher Block Chaining",
        'PCFB'      => "Periodic Cipher Feedback Mode",
        'PCT'       => "Private Communications Transport",
        'PEM'       => "Privacy Enhanced Mail",
        'PES'       => "Proposed Encryption Standard",
        'PFS'       => "Perfect Forward Secrecy",
        'PFX'       => "see PKCS#12",
#       'PFX'       => "Personal Information Exchange", # just for info
        'PGP'       => "Pretty Good Privacy",
        'PII'       => "Personally Identifiable Information",
        'PKCS'      => "Public Key Cryptography Standards",
        'PKCS1'     => "PKCS #1: RSA Encryption Standard",
        'PKCS3'     => "PKCS #3: RSA Encryption Standard on how to implement the Diffie-Hellman key exchange protocol",
        'PKCS5'     => "PKCS #5: RSA Encryption Standard on how to derive cryptographic keys from a password",
        'PKCS6'     => "PKCS #6: RSA Extended Certificate Syntax Standard",
        'PKCS7'     => "PKCS #7: RSA Cryptographic Message Syntax Standard",
        'PKCS8'     => "PKCS #8: RSA Private-Key Information Syntax Standard",
        'PKCS10'    => "PKCS #10: Describes a standard syntax for certification requests",
        'PKCS11'    => "PKCS #11: RSA Cryptographic Token Interface Standard (keys in hardware devices, cards)",
        'PKCS12'    => "PKCS #12: RSA Personal Information Exchange Syntax Standard (public + private key stored in files)",
        'PKI'       => "Public Key Infrastructure",
        'PKIX'      => "Internet Public Key Infrastructure Using X.509",
        'PKP'       => "Public-Key-Pins",
        'PM'        => "Policy Mappings (certificate extension)",
        'PMAC'      => "Parallelizable MAC (by Phillip Rogaway)",
        'PMS'       => "pre-master secret",
        'Poly1305-AES'  => "MAC (by D. Bernstein)",
        'POP'       => "Proof of Possession",
        'POODLE'    => "Padding Oracle On Downgraded Legacy Encryption",
        'PRF'       => "pseudo-random function",
        'PRNG'      => "pseudo-random number generator",
        'PSK'       => "Pre-shared Key",
        'PWKE'      => "Pair-Wise Key Establishment Schemes Using Discrete Logarithm Cryptography",
        'QUIC'      => "Quick UDP Internet Connection",
        'RA'        => "Registration Authority (aka Registration CA)",
        'Rabbit'    => "stream cipher algorithm",
        'RADIUS'    => "Remote Authentication Dial-In User Service",
        'Radix-64'  => "alias for Base-64",
        'RBG'       => "Random Bit Generator",
        'RC2'       => "Rivest Cipher 2, block cipher by Ron Rivest (64-bit blocks)",
        'RC4'       => "Rivest Cipher 4, stream cipher (aka Ron's Code)",
        'RC5'       => "Rivest Cipher 5, block cipher (32-bit word)",
        'RC5-64'    => "Rivest Cipher 5, block cipher (64-bit word)",
        'RC6'       => "Rivest Cipher 6",
        'RCSU'      => "Reuters' Compression Scheme for Unicode (aka SCSU)",
        'RFC'       => "Request for Comments",
        'Rijndael'  => "symmetric block cipher algorithm",
        'RIPEMD'    => "RACE Integrity Primitives Evaluation Message Digest",
        'RMAC'      => "Randomized MAC (block cipher authentication mode)",
        'RNG'       => "Random Number Generator",
        'ROT-13'    => "see XOR",
        'RTP'       => "Real-time Transport Protocol",
        'RSA'       => "Rivest Sharmir Adelman (public key cryptographic algorithm)",
        'RSS-14'    => "Reduced Space Symbology, see GS1",
        'RTN'       => "Routing transit number",
        'S/KEY'     => "One-time pad Password system",
        'SA'        => "Subordinate Authority (aka Subordinate CA)",
        'SACL'      => "System Access Control List",
        'SAFER'     => "Secure And Fast Encryption Routine, block cipher",
        'Salsa20'   => "stream cipher",
        'SAM'       => "syriac abbreviation mark",
        'SAN'       => "Subject Alternate Name",
        'SAX'       => "Symmetric Authenticated eXchange",
        'SCA'       => "Selfsigned CA signature",
        'SBCS'      => "single-byte character set",
        'SCEP'      => "Simple Certificate Enrollment Protocol",
        'SCSU'      => "Standard Compression Scheme for Unicode (compressed UTF-16)",
        'SCSV'      => "Signaling Cipher Suite Value",
        'SCVP'      => "Server-Based Certificate Validation Protocol",
        'SCT'       => "Signed Certificate Timestamp",
        'SDES'      => "Security Description Protokol",
        'SEED'      => "128-bit Symmetric Block Cipher",
        'Serpent'   => "symmetric key block cipher (128 bit)",
        'SGC'       => "Server-Gated Cryptography",
        'SHA'       => "Secure Hash Algorithm",
        'SHA-0'     => "Secure Hash Algorithm (insecure version before 1995)",
        'SHA-1'     => "Secure Hash Algorithm (since 1995)",
        'SHA-2'     => "Secure Hash Algorithm (since 2002)",
        'SHA-224'   => "Secure Hash Algorithm (224 bit)",
        'SHA-256'   => "Secure Hash Algorithm (256 bit)",
        'SHA-384'   => "Secure Hash Algorithm (384 bit)",
        'SHA-512'   => "Secure Hash Algorithm (512 bit)",
        'SHA1'      => "alias for SHA-1 (160 bit)",
        'SHA2'      => "alias for SHA-2 (224, 256, 384 or 512 bit)",
        'SHS'       => "Secure Hash Standard",
        'SIA'       => "Subject Information Access (certificate extension)",
        'SIC'       => "Segmented Integer Counter (alias for CTR)",
        'Skein'     => "hash function",
        'SKID'      => "subject key ID (certificate extension)",
        'SKIP'      => "Message Skipping Attacks on TLS",
        'SKIP-TLS'  => "see SKIP",
        'Skipjack'  => "block cipher encryption algorithm specified as part of the Fortezza",
        'SLOTH'     => "Security Losses from Obsolete and Truncated Transcript Hashes",
        'SMACK'     => "State Machine AttaCKs",
        'Snefu'     => "hash function",
        'SNI'       => "Server Name Indication",
        'SNOW'      => "word-based synchronous stream ciphers (by Thomas Johansson and Patrik Ekdahl )",
        'SPDY'      => "Google's application-layer protocol on top of SSL",
        'SPKI'      => "Subject Public Key Infrastructure",
        'SPN'       => "Substitution-Permutation Network",
        'Square'    => "block cipher",
        'SRI'       => "Subresource Integrity",
        'SRP'       => "Secure Remote Password protocol",
        'SRTP'      => "Secure RTP",
        'SSCD'      => "Secure Signature Creation Device",
        'SSEE'      => "Sichere Signaturerstellungseinheit (same as SSCD)",
        'SSL'       => "Secure Sockets Layer",
        'SSLv2'     => "Secure Sockets Layer Version 2",
        'SSLv3'     => "Secure Sockets Layer Version 3",
        'SSP'       => "Security Support Provider",
        'SSPI'      => "Security Support Provider Interface",
        'SST'       => "Serialized Certificate Store format",
        'SCT'       => "Signed Certificate Timestamp",
        'STS'       => "Strict Transport Security",
        'STS '      => "Station-to-Station protocol",
        'TACK'      => "Trust Assertions for Certificate Keys",
        'TCB'       => "Trusted Computing Base",
        'TDEA'      => "Tripple DEA",
        'TEA'       => "Tiny Encryption Algorithm",
        'TEK'       => "Traffic Encryption Key",
        'Tiger'     => "hash function",
        'TIME'      => "Timing Info-leak Made Easy (Exploit SSL/TLS)",
        'TIME '     => "A Perfect CRIME? TIME Will Tell",
        'Threefish' => "hash function",
        'TLSA'      => "alias for TLSA RR",
        'TLSA RR'   => "TLSA resource Record",
        'TMAC'      => "Two-Key CMAC, variant of CBC-MAC",
        'TOCTOU'    => "Time-of-check, time-of-use",
        'TOFU'      => "Trust on First Use",
        'TR-02102'  => "Technische Richtlinie 02102 (des BSI)",
        'TR-03116'  => "Technische Richtlinie 03116 (des BSI)",
        'TLS'       => "Transport Layer Security",
        'TLSA'      => "TLS Trust Anchors",
        'TLSv1'     => "Transport Layer Security version 1",
        'TSK'       => "Transmission Security Key",
        'TSK '      => "TACK signing key",
        'TSP'       => "trust-Management Service Provider",
        'TSS'       => "Time Stamp Service",
        'TTP'       => "trusted Third Party",
        'Twofish'   => "symmetric key block cipher (128 bit)",
        'UC'        => "Unified Communications (SSL Certificate using SAN)",
        'UCC'       => "Unified Communications Certificate (rarley used)",
        'UMAC'      => "Universal hashing MAC; optimized for 32-bit architectures",
        'VMAC'      => "Universal hashing MAC; 64-bit variant of UMAC (by Ted Krovetz and Wei Dai)",
        'VMPC'      => "stream cipher",
        'WHIRLPOOL' => "hash function",
        'X.680'     => "X.680: ASN.1",
        'X.509'     => "X.509: The Directory - Authentication Framework",
        'X680'      => "X.680: ASN.1",
        'X509'      => "X.509: The Directory - Authentication Framework",
        'XCBC'      => "eXtended CBC-MAC",
        'XCBC-MAC'  => "same as XCBC",
        'XKMS'      => "XML Key Management Specification",
        'XMACC'     => "counter-based XOR-MAC",
        'XMACR'     => "radomized XOR-MAC",
        'XMLSIG'    => "XML-Signature Syntax and Processing",
        'XTEA'      => "extended Tiny Encryption Algorithm",
        'XUDA'      => "Xcert Universal Database API",
        'XXTEA'     => "enhanced/corrected Tiny Encryption Algorithm",
        'ZLIB'      => "Lossless compression file format",
        'ZSK'       => "Zone Signing Key", # DNSSEC
    },

    'rfc' => {
        # number   [ title / description                     additional information ],
        #----------+----------------------------------------+-----------------------+
        'url'   => [ "base URL for RFC descriptions",        "http://tools.ietf.org/" ],
                   # http://tools.ietf.org/html/rfcXXXX
                   # http://tools.ietf.org/rfc/rfcXXXX.txt
        '6167'  => [ "Prohibiting Secure Sockets Layer (SSL) Version 2.0" ],
        '6101'  => [ "SSL Version 3.0"  ],
        '2246'  => [ "TLS Version 1.0"  ],
        '4346'  => [ "TLS Version 1.1"  ],
        '5246'  => [ "TLS Version 1.2"  ],
        '4347'  => [ "DTLS Version 0.9" ],
        '6347'  => [ "DTLS Version 1.2" ],
        '3490'  => [ "Internationalizing Domain Names in Applications (IDNA)" ],
        '3987'  => [ "Internationalized Resource Identifiers (IRIs)" ],
        '4518'  => [ "Internationalized String Preparation in LDAP" ],
        '3986'  => [ "Uniform Resource Identifier (URI): Generic Syntax" ],
        '2104'  => [ "HMAC: Keyed-Hashing for Message Authentication" ],
        '2412'  => [ "AKLEY Key Determination Protocol (PFS - Perfect Forward Secrec')",
                     "http://en.wikipedia.org/wiki/Perfect_forward_secrecy"
                   ],
    #           alle *DH* sind im Prinzip PFS.
    #           wird manchmal zusaetzlich mit DHE bezeichnet, wobei E für ephemeral
    #           also flüchtige, vergängliche Schlüssel steht
    #           D.H. ECDHE_* und DHE_* an den Anfang der Cipherliste stellen, z.B.
    #                TLS_ECDHE_RSA_WITH_RC4_128_SHA
    #                TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    #                TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    #                TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA 
        '2818'  => [ "HTTP Over TLS" ],
        '2945'  => [ "SRP Authentication & Key Exchange System" ],
        '2986'  => [ "PKCS#10" ],
        '5967'  => [ "PKCS#10" ],
        '5081'  => [ "TLSPGP: Using OpenPGP Keys for Transport Layer Security (TLS) Authentication" ],
        '4309'  => [ "AES-CCM Mode with IPsec Encapsulating Security Payload (ESP)" ],
        '5116'  => [ "An Interface and Algorithms for Authenticated Encryption (AEAD)" ],
        '3749'  => [ "TLS Compression Method" ],
        '3943'  => [ "TLS Protocol Compression Using Lempel-Ziv-Stac (LZS)" ],
        '3546'  => [ "TLS Extensions", "obsolete" ],
        '4366'  => [ "TLS Extensions" ],
                   # AKID - authority key identifier
                   # Server name Indication (SNI): server_name
                   # Maximum Fragment Length Negotiation: max_fragment_length
                   # Client Certificate URLs: client_certificate_url
                   # Trusted CA Indication: trusted_ca_keys
                   # Truncated HMAC: truncated_hmac
                   # Certificate Status Request (i.e. OCSP stapling): status_request
                   # Error Alerts
        '4749'  => [ "TLS Compression Methods" ],
        '5077'  => [ "TLS session resumption" ],
        '5746'  => [ "TLS Renegotiation Indication Extension" ],
        '5764'  => [ "TLS Extension: SRTP" ],
        '5929'  => [ "TLS Extension: Channel Bindings", "tls-unique" ],
        '6066'  => [ "TLS Extension: Extension Definitions" ],
                   # PkiPath
                   # Truncated CA keys (value 3)
                   # Truncated HMAC (value 4)
                   # (Certificate) Status Request (value 5)
        '6520'  => [ "TLS Extensions: Heartbeat" ],
        '6961'  => [ "TLS Multiple Certificate Status Request Extension" ],
        '7627'  => [ "TLS Session Hash and Extended Master Secret Extension" ],
        '6460'  => [ "NSA Suite B Profile for TLS" ],
        '2560'  => [ "Online Certificate Status Protocol (OCSP)", "obsolete" ],
        '6267'  => [ "Online Certificate Status Protocol Algorithm Agility (OCSP)", "obsolete" ],
        '4210'  => [ "X509 PKI Certificate Management Protocol (CMP)" ],
        '3279'  => [ "x509 Algorithms and Identifiers for X.509 PKI and CRL Profile" ],
        '3739'  => [ "x509 PKI Qualified Certificates Profile; EU Directive 1999/93/EC" ],
        '3280'  => [ "X509 PKI Certificate and Certificate Revocation List (CRL) Profile", "obsolete" ],
        '4158'  => [ "X509 PKI Certification Path Building" ],
        '4387'  => [ "X509 PKI Operational Protocols: Certificate Store Access via HTTP" ],
        '5280'  => [ "X509 PKI Certificate and Certificate Revocation List (CRL) Profile" ],
        '6960'  => [ "X509 Online Certificate Status Protocol (OCSP)",
                     "http://en.wikipedia.org/wiki/OCSP_stapling" ],
                   #
       #'2246'  => [ "TLS Version 1.0"  ], # with Cipher Suites
        '2712'  => [ "TLSKRB: Addition of Kerberos Cipher Suites to TLS" ],
        '3268'  => [ "TLSAES: Advanced Encryption Standard (AES) Cipher Suites for TLS" ],
        '4132'  => [ "Addition of Camellia Cipher Suites to TLS" ],
        '4162'  => [ "Addition of SEED Cipher Suites to TLS" ],
        '4279'  => [ "TLSPSK: Pre-Shared Key Ciphersuites for TLS" ],
       #'4346'  => [ "TLS Version 1.1"  ], # with Cipher Suites
        '4357'  => [ "Additional Cryptographic Algorithms for Use with GOST 28147-89, GOST R 34.10-94, GOST R 34.10-2001, and GOST R 34.11-94 Algorithms" ],
        '4491'  => [ "Using the GOST Algorithms with X509" ],
                   # GOST R 34.10-94, GOST R 34.10-2001, GOST R 34.11-94
        '4492'  => [ "TLSECC: Elliptic Curve Cryptography (ECC) Cipher Suites for TLS" ],
        '4785'  => [ "Pre-Shared Key (PSK) Cipher Suites with NULL Encryption for TLS" ],
        '5054'  => [ "Secure Remote Password (SRP) Protocol for TLS Authentication" ],
       #'5246'  => [ "TLS Version 1.2"  ], # with Cipher Suites
        '5288'  => [ "AES Galois Counter Mode (GCM) Cipher Suites for TLS" ],
        '5289'  => [ "TLS Elliptic Curve Cipher Suites with SHA-256/384 and AES Galois Counter Mode (GCM)" ],
        '5430'  => [ "Suite B Profile for TLS" ],
        '5487'  => [ "Pre-Shared Key Cipher Suites for TLS with SHA-256/384 and AES Galois Counter Mode" ],
        '5489'  => [ "ECDHE_PSK Cipher Suites for TLS" ],
        '5589'  => [ "Session Initiation Protocol (SIP) Call Control - Transfer" ],
        '5741'  => [ "RFC Streams, Headers, and Boilerplates" ],
        '5794'  => [ "Description of the ARIA Encryption Algorithm" ],
        '5932'  => [ "Camellia Cipher Suites for TLS" ],
        '6209'  => [ "Addition of the ARIA Cipher Suites to TLS" ],
        '6367'  => [ "Addition of the Camellia Cipher Suites to TLS" ],
        '6655'  => [ "AES-CCM Cipher Suites for TLS" ],
        '7251'  => [ "AES-CCM Elliptic Curve Cryptography (ECC) Cipher Suites for TLS" ],
        '7507'  => [ "TLS Fallback Signaling Cipher Suite Value (SCSV) for Preventing Protocol Downgrade Attacks" ],
                   #
        '5055'  => [ "Server-Based Certificate Validation Protocol (SCVP)" ],
        '5019'  => [ "simplified RFC 2560" ],
        '5705'  => [ "Keying Material Exporters for TLS" ],
        '6125'  => [ "Representation and Verification of Domain-Based Application Service (PKIX) for TLS" ],
                   # Representation and Verification of Domain-Based Application Service
                   # Identity within Internet Public Key Infrastructure Using X.509 (PKIX)
                   # Certificates in the Context of Transport Layer Security (TLS)
        '6797'  => [ "HTTP Strict Transport Security (HSTS)" ],
        '6962'  => [ "Certificate Transparency" ],
        '7457'  => [ "Summarizing Known Attacks on TLS and DTLS" ],
        '7469'  => [ "Public Key Pinning Extension for HTTP" ],
        '7525'  => [ "Recommendations for Secure Use of TLS and DTLS" ],
        '7539'  => [ "ChaCha20 and Poly1305 for IETF Protocols" ],
        '7905'  => [ "ChaCha20-Poly1305 Cipher Suites for TLS" ],
        #----------+----------------------------------------+-----------------------+
    },

    # Additional informationes:
    # CT   : http://ctwatch.net/
    # AIA  : http://www.startssl.com/certs/sub.class4.server.ca.crt
    # CDP  : http://www.startssl.com/crt4-crl.crl, http://crl.startssl.com/crt4-crl.crl
    # OCSP : http://ocsp.startssl.com/sub/class4/server/ca
    # cat some.crl | openssl crl -text -inform der -noout
    # OCSP response "3" (TLS 1.3) ==> certifcate gueltig
    # SPDY - SPDY Protocol : http://www.chromium.org/spdy/spdy-protocol
    # False Start: https://www.imperialviolet.org/2012/04/11/falsestart.html
    #              https://technotes.googlecode.com/git/falsestart.html
    # ALPN : http://tools.ietf.org/html/draft-friedl-tls-applayerprotoneg-02
    #        https://tools.ietf.org/html/rfc7301
    #        ExtensionType Values 16
    #        ProtocolNameList: 
    #        Protocol:  HTTP/1.1
    #           Identification Sequence: http/1.1
    #        Protocol:  SPDY/1
    #           Identification Sequence: spdy/1
    #        Protocol:  SPDY/2
    #           Identification Sequence: spdy/2
    #        Protocol:  SPDY/3
    #           Identification Sequence: spdy/3
    #        Application-Layer Protocol Negotiation (ALPN) is available with
    #        Net::SSLeay 1.56+ and +openssl-1.0.2+.
    #        Check support with: 'IO::Socket::SSL->can_alpn()'.
    #        Note that some client implementations may encounter problems if
    #        both NPN and ALPN are +specified. Since ALPN is intended as a
    #        replacement for NPN, try providing ALPN protocols +then fall back
    #        to NPN if that fails.
    # SPDY/3 http://dev.chromium.org/spdy/spdy-protocol/spdy-protocol-draft3
    # ALPN, NPN: https://www.imperialviolet.org/2013/03/20/alpn.html
    # NPN  : https://technotes.googlecode.com/git/nextprotoneg.html
    # HSTS : http://tools.ietf.org/html/draft-hodges-strict-transport-sec-02
    #        https://www.owasp.org/index.php/HTTP_Strict_Transport_Security
    #        Strict-Transport-Security: max-age=16070400; includeSubDomains
    #        Apache config:
    #             Header set Strict-Transport-Security "max-age=16070400; includeSubDomains"
    # SNI apache: https://wiki.apache.org/httpd/NameBasedSSLVHostsWithSNI
    #        SSLStrictSNIVHostCheck, which controls whether to allow non SNI clients to access a name-based virtual host. 
    #        when client provided the hostname using SNI, the new environment variable SSL_TLS_SNI
    # TLS session resumption problem with session ticket
    #        see https://www.imperialviolet.org/2011/11/22/forwardsecret.html
    #        "Since the session ticket contains the state of the session, and
    #         thus keys that can decrypt the session, it too must be protected
    #         by ephemeral keys. But, in order for session resumption to be
    #         effective, the keys protecting the session ticket have to be kept
    #         around for a certain amount of time: the idea of session resumption
    #         is that you can resume the session in the future, and you can't
    #         do that if the server can't decrypt the ticket!
    #         So the ephemeral, session ticket keys have to be distributed to
    #         all the frontend machines, without being written to any kind of
    #         persistent storage, and frequently rotated."
    #        see also https://www.imperialviolet.org/2013/06/27/botchingpfs.html
    #
    # TACK   http://tack.io/draft.html, 2013 Moxie Marlinspike, Trevor Perrin
    #
    # SCSV   https://datatracker.ietf.org/doc/draft-bmoeller-tls-downgrade-scsv/?include_text=1
    # SRI    Subresource Integrity: https://www.w3.org/TR/SRI/ 4/2016
    #        see also: https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
    #        supported by: Chrome 45, Firefox 43, Opera 32
    #        Note that SRI is SSL/TLS-related but security-related
    # TS 102 042 : http://
    #
    # Firefox Add-ons
    #        https://calomel.org/firefox_ssl_validation.htm  Calomel SSL Validation
    #        https://addons.mozilla.org/de/firefox/addon/cert-viewer-plus/   Cert Viewer Plus
    #
    #        http://patrol.psyced.org/       Certifiate Patrol
    #        certwatch.simos.info            CertWatch
    #
); # %man_text

#| definitions: internal functions
#| -------------------------------------
sub _man_dbx(@) { my @txt=@_; print "#" . $ich . " CMD: " . join(" ", @txt, "\n") if ((grep{/^--(?:v|trace.?CMD)/i} @ARGV)>0); return; } # similar to _y_CMD
    # When called from within parent's BEGIN{} section, options are not yet
    # parsed, and so not available in %cfg. Hence we use @ARGV to check for
    # options, which is not performant, but fast enough here.

sub _man_http_head(){
    return if ((grep{/--cgi/} @ARGV) <= 0);
    # checking @ARGV for --cgi is ok, as this option is for simulating
    # CGI mode only.
    # When called from o-saft.cgi, HTTP headers are already written.
    print "X-Cite: Perl is a mess. But that's okay, because the problem space is also a mess. Larry Wall\r\n";
    print "Content-type: text/html; charset=utf-8\r\n";
    print "\r\n";
    return;
}

sub _man_html_head(){
    _man_dbx("_man_html_head() ...");
    print << "EoHTML";
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title> . :  O - S a f t  &#151;  OWASP SSL advanced forensic tool : . </title>
<script>
function d(id){return document.getElementById(id).style;}
function t(id){id.display=(id.display=='none')?'block':'none';}
</script>
<style>
 .r{float:right;}
 .c{!font-size:12pt !important;border:1px none black;font-family:monospace;background-color:lightgray;}
 p{margin-left:2em;margin-top:0;}
 h2, h3, h4, h5{margin-bottom:0.2em;}
 h2{margin-top:-0.5em;padding:1em;height:1.5em;background-color:black;color:white;}
 li{margin-left:2em;}
 div{padding:0.5em;border:1px solid green;}
 div[class=c]{padding:0pm;padding:0.1em;margin-left:4em;border:0px solid green;}
 form{padding:1em;}
 span{font-size:120%;border:1px solid green;}
</style>
</head>
<body>
 <h2>O - S a f t &#160; &#151; &#160; OWASP SSL advanced forensic tool</h2><!-- hides unwanted text before <body> tag -->
EoHTML
    return;
}
sub _man_html_foot(){
    _man_dbx("_man_html_foot() ...");
    print << "EoHTML";
 <a href="https://github.com/OWASP/O-Saft/"   target=_github >Repository</a> &nbsp;
 <a href="https://github.com/OWASP/O-Saft/blob/master/o-saft.tgz" target=_tar ><button value="" />Download (stable)</button></a><br>
 <a href="https://owasp.org/index.php/O-Saft" target=_owasp  >O-Saft Home</a>
 <hr><p><span>&copy; sic[&#x2713;]sec GmbH, 2012 - 2016</span></p>
</body></html>
EoHTML
    return;
}

sub _man_html_chck($){
    #? same as _man_html_cbox() but without lable and only if passed parameter start with - or +
    my $n = shift || "";
    return "" if ($n !~ m/^(?:-|\+)+/);
    return sprintf("<input type=checkbox name='%s' value='' >&#160;", scalar((split(/\s+/,$n))[0]));
}
sub _man_name_ankor($){
    my $n = shift;
    $n =~ s/,//g;  # remove comma
    #$n =~ s/\s/_/g;# replace spaces
    return $n;
}
sub _man_html_ankor($){
    #? print ankor tag for each word in given parameter
    my $n = shift;
    my $a = "";
    return sprintf('<a name="a%s"></a>', $n) if ($n !~ m/^[-\+]+/);
    foreach my $n (split(/[\s,]+/,$n)) {
        $a .= sprintf("<a name='a%s'></a>", _man_name_ankor($n));
    }
    return $a;
}
sub _man_html_cbox($) { my $key = shift; return sprintf("%8s--%-10s<input type=checkbox name=%-12s value='' >&#160;\n", "", $key, '"--' . $key . '"'); }
sub _man_html_text($) { my $key = shift; return sprintf("%8s--%-10s<input type=text     name=%-12s size=8 >&#160;\n", "", $key, '"--' . $key . '"'); }
sub _man_html_span($) { my $key = shift; return sprintf("%8s<span>%s</span><br>\n", "", $key); }
sub _man_html_cmd($)  { my $key = shift; return sprintf("%9s+%-10s<input type=text     name=%-12s size=8 >&#160;\n", "", "", '"--' . $key . '"'); }

sub _man_html_br()    { return sprintf("        <br>\n"); }

sub _man_html($$) {
    my $anf = shift; # pattern where to start extraction
    my $end = shift; # pattern where to stop extraction
    my $h = 0;
    _man_dbx("_man_html($anf, $end) ...");
    while ($_ = shift @DATA) {
        last if/^TODO/;
        $h=1 if/^=head1 $anf/;
        $h=0 if/^=head1 $end/;
        next if $h==0;                              # ignore "out of scope"
        m/^=head1 (.*)/   && do { printf("\n<h1>%s %s </h1>\n",_man_html_ankor($1),$1);next;};
        m/^=head2 (.*)/   && do { printf("%s\n<h3>%s %s </h3> <p onclick='t(this);return false;'>\n",_man_html_ankor($1),_man_html_chck($1),$1);next;};
        m/^=head3 (.*)/   && do { printf("%s\n<h4>%s %s </h4> <p onclick='t(this);return false;'>\n",_man_html_ankor($1),_man_html_chck($1),$1);next;};
        m/^\s*S&([^&]*)&/ && do { print "<div class=c >$1</div>\n"; next; }; # code or example line
        s!'([^']*)'!<span class=c >$1</span>!g;     # markup examples
        s!"([^"]*)"!<cite>$1</cite>!g;              # markup examples
        s!L&([^&]*)&!<i>$1</i>!g;                   # markup other references
        s!I&([^&]*)&!<a href="#a$1">$1</a>!g;       # markup commands and options
        s!X&([^&]*)&!<a href="#a$1">$1</a>!g;       # markup references inside help
        s!^\s+($parent .*)!<div class=c >$1</div>!; # example line
        m/^=item +\* (.*)/&& do { print "<li>$1</li>\n";next;}; # very lazy ...
        m/^=item +\*\* (.*)/  && do{ print "<li type=square style='margin-left:3em'>$1 </li>\n";next;};
        s/^(?:=[^ ]+ )//;                           # remove remaining markup
        s/^\s*$/<p>/;                               # add paragraph for formatting
        print;
    }
    return;
} # _man_html

sub _man_head(@) {
    my @args = @_;
    _man_dbx("_man_head(..) ...");
    return if ($cfg_header < 1);
    printf("=%14s | %s\n", @args);
    printf("=%s+%s\n", '-'x15, '-'x60);
    return;
}
sub _man_foot() {
    return if ($cfg_header < 1);
    printf("=%s+%s\n", '-'x15, '-'x60);
    return;
}
sub _man_opt(@) {
    my @args = @_;
    my $len  = 16;
       $len  = 1 if ($args[1] eq "="); # allign left for copy&paste
    printf("%${len}s%s%s\n", @args);
    return;
}
sub _man_arr($$$) {
    my ($ssl, $sep, $dumm) = @_;
    my @all = ();
    push(@all, sprintf("0x%08X",$_)) foreach (@{$cfg{'cipherranges'}->{$ssl}});
    printf("%16s%s%s\n", $ssl, $sep, join(" ", @all));
    return;
}
sub _man_cfg($$$$){
    #? print line in configuration format
    my ($typ, $key, $sep, $txt) = @_;
    $txt =  '"' . $txt . '"' if ($typ =~ m/^cfg/);
    $key =  "--$typ=$key"    if ($typ =~ m/^cfg/);
    _man_opt($key, $sep, $txt);
    return;
}

sub _man_usr_value($)   {
    #? return value of argument $_[0] from @{$cfg{'usr-args'}}
    my $key =  shift;
       $key =~ s/^(?:--|\+)//;  # strip leading chars
    my @arg =  "";              # key, value (Note that value is anything right to leftmost = )
    map({@arg = split(/=/, $_, 2) if /^$key/} @{$cfg{'usr-args'}}); # does not allow multiple $key in 'usr-args'
    return $arg[1];
} # _man_usr_value

#| definitions: print functions for help and information
#| -------------------------------------

sub man_table($) { ## no critic qw(Subroutines::ProhibitExcessComplexity)
    #? print data from hash in tabular form, $typ denotes hash
    #? header of table is not printed if $typ is cfg-*
    #  NOTE critic: McCabe 22 (tested 5/2016) is not that bad here ;-)
    my $typ = shift;
    my %types = (
        # typ        header left    separator  header right
        #-----------+---------------+-------+-------------------------------
        'score' => ["key",           " - ",  " SCORE\t# Description"],
        'regex' => ["key",           " - ",  " Regular Expressions used internally"],
        'ourstr'=> ["key",           " - ",  " Regular Expressions to match own output"],
        'abbr'  => ["Abbrevation",   " - ",  " Description"],
        'intern'=> ["Command",       "    ", " list of commands"],
        'compl' => ["Compliance",    " - ",  " Brief description of performed checks"],
        'range' => ["range name",    " - ",  " hex values in this range"],
        'rfc'   => ["Number",        " - ",  " RFC Title and URL"],
        'check' => ["key",           " - ",  " Label text"],
        'data'  => ["key",           " - ",  " Label text"],
        'hint'  => ["key",           " - ",  " Hint text"],
        'text'  => ["key",           " - ",  " text"],
    );
    my $txt = "";
    my $sep = "\t";
    if (defined $types{$typ}) { # defensive programming
       $sep = $types{$typ}->[1];
    } else {
       $sep = "=" if ($typ =~ m/(?:^cfg[_-]|[_-]cfg$)/);
            # the purpose of cfg_* is to print the results in a format so that
            # they can be used with copy&paste as command line arguments
            # simply change the separator to =  while other headers are unused
            # (because no header printed at all)
    }
    _man_dbx("man_table($typ) ...");
    _man_head($types{$typ}->[0], $types{$typ}->[2]) if ($typ !~ m/^cfg/);

    # first only lists, which cannot be redefined with --cfg-*= (doesn't make sense)
    if ($typ eq 'rfc')   { _man_opt("RFC $_", $sep, $man_text{'rfc'}->{$_}[0] . "\n\t\t\t$man_text{'rfc'}->{url}[1]/html/rfc$_") foreach (sort keys %{$man_text{'rfc'}}); }
    if ($typ eq 'abbr')  { _man_opt(do{(my $a=$_)=~s/ *$//;$a}, $sep, $man_text{'glossar'}->{$_}) foreach (sort keys %{$man_text{'glossar'}}); }
    if ($typ eq 'compl') { _man_opt($_, $sep, $cfg{'compliance'}->{$_})    foreach (sort keys %{$cfg{'compliance'}}); }
    if ($typ eq 'intern') {
        foreach my $key (sort keys %cfg) {
            next if ($key eq 'cmd-intern'); # don't list myself
            next if ($key !~ m/^cmd-(.*)/);
            _man_opt("cmd-" . $1, $sep, "+" . join(" +", @{$cfg{$key}}));
        }
    }

    # now all lists, which can be redefined with --cfg-*=
    # _man_cfg() prints different data for  --help=TYP and --help=TYP-cfg
    if ($typ =~ m/(hint|ourstr|range|regex)/) {
        my $list = $1;
           $list =~ s/^cfg[._-]?//;
           $list =~ s/[._-]?cfg$//;
           $list =  'hints' if ($list =~ m/hint/);  # the key in %cfg is 'hints'; 'hint' is different
           $list =  'cipherranges' if ($list =~ m/range/);
        # TODO: --cfg_range=* and --cfg-regex=*  are not yet implemented
        #       however, we can print it using --help=cfg-regex
        foreach my $key (sort keys %{$cfg{$list}}) {
            $txt =  $cfg{$list}->{$key};
            _man_cfg($typ, $key, $sep, $txt);
        }
    }
    if ($typ =~ m/score/) {
        foreach my $key (sort keys %checks) {
            $txt =  $checks{$key}->{score} . "\t# " . $checks{$key}->{txt};
            $txt =  $checks{$key}->{score} if ($typ =~ m/cfg/);
            _man_cfg($typ, $key, $sep, $txt);
        }
    }
    if ($typ =~ m/check/) {
        foreach my $key (sort keys %checks) {
            $txt =  $checks{$key}->{txt};
            _man_cfg($typ, $key, $sep, $txt);
        }
    }
    if ($typ =~ m/data/) {
        foreach my $key (sort keys %data) {
            $txt =  $data{$key}->{txt};
            _man_cfg($typ, $key, $sep, $txt);
        }
    }
    if ($typ =~ m/text/) {
        foreach my $key (sort keys %text) {
            next if (ref($text{$key}) ne ""); # skip except string
            $txt =  $text{$key};
            $txt =~ s/(\n)/\\n/g;
            $txt =~ s/(\r)/\\r/g;
            $txt =~ s/(\t)/\\t/g;
            _man_cfg($typ, $key, $sep, $txt);
        }
    }
    if ($typ !~ m/cfg/) {
        _man_foot();
    } else {
        # additional message here is like a WARNING or Hint,
        # do not print it if any of them is disabled
        return if (($cfg{'warning'} + $cfg{'hint'}) < 2);
        my $q = '"';
        print "
= Format is:  KEY=TEXT ; NL, CR and TAB are printed as \\n, \\r and \\t
= (Don't be confused about multiple  =  as they are part of  TEXT.)
= The string  @@  inside texts is used as placeholder.
= NOTE: $q are not escaped!
";
    }
    return;
} # man_table

sub man_commands() {
    #? print commands and short description
    # data is extracted from $parents internal data structure
    my $skip = 1;
    my $fh   = undef;
    _man_dbx("man_commands($parent) ...");
    # first print general commands, manually crafted here
    # TODO needs to be computed, somehow ...
    print "\n";
    _man_head("Command", "Description");
    print <<"EoHelp";
                  Commands for information about this tool
+dump             Dumps internal data for SSL connection and target certificate.
+exec             Internal command; should not be used directly.
+help             Complete documentation.
+list             Show all ciphers supported by this tool.
+libversion       Show version of openssl.
+quit             Show internal data and exit, used for debugging only.
+VERSION          Just show version and exit.
+version          Show version information for program and Perl modules.

                  Commands to check SSL details
+bsi              Various checks according BSI TR-02102-2 and TR-03116-4 compliance.
+check            Check the SSL connection for security issues.
+check_sni        Check for Server Name Indication (SNI) usage.
+ev               Various checks according certificate's extended Validation (EV).
+http             Perform HTTP checks.
+info             Overview of most important details of the SSL connection.
+info--v          More detailled overview.
+quick            Quick overview of checks.
+s_client         Dump data retrieved from  "openssl s_client ..."  call.
+sizes            Check length, size and count of some values in the certificate.
+sni              Check for Server Name Indication (SNI) usage.
+sts              Various checks according STS HTTP header.

                  Commands to test target's ciphers
+cipher           Check target for ciphers (using libssl)
+cipherraw        Check target for all possible ciphers.

EoHelp

    if (open($fh, '<:encoding(UTF-8)', $0)) { # need full path for $parent file here
        while(<$fh>) {
            # find start of data structure
            # all structure look like:
            #    our %check_some = ( # description
            #          'key' => {... 'txt' => "description of value"},
            #    );
            # where we extract the description of the checked class from first
            # line and the command and its description from the data lines
            if (m/^(?:my|our)\s+%(?:check_(?:[a-z0-9_]+)|data)\s*=\s*\(\s*##*\s*(.*)/) {
                $skip = 0;
                print "\n                  Commands to show results of checked $1\n";
                next;
            }
            $skip = 1, next if (m/^\s*\)\s*;/); # find end of data structure
            next if ($skip == 1);
            next if (m/^\s*'(?:SSLv2|SSLv3|D?TLSv1|TLSv11|TLSv12|TLSv13)-/); # skip internal counter
            my $t   = "\t";
           #   $t  .= "\t" if (length($1) < 7);
            printf("+%-17s%s\n", $1, $2) if m/^\s+'([^']*)'.*"([^"]*)"/;
        }
        close($fh);
    }
    _man_foot();
    print "\n";
    return;
} # man_commands

sub man_alias() {
    #? print alias and short description (if available)
    #
    # Aliases are extracted from the source code. All lines handling aliases
    # for commands or options are marked with the pattern  # alias:
    # From these lines we extract the regex, the real option or command and
    # the comment.
    #
    #                 /------- regex -------\         /--- command ----\  /pattern\ /--- comment ---
    # Examples of lines to match:
    #    if ($arg eq  '--nosslnodataeqnocipher'){$arg='--nodatanocipher';} # alias:
    #    if ($arg =~ /^--ca(?:cert(?:ificate)?)$/i)  { $arg = '--cafile';} # alias: curl, openssl, wget, ...
    #    if ($arg =~ /^--cadirectory$/i)     { $arg = '--capath';        } # alias: curl, openssl, wget, ...
    #    if ($arg eq  '-c')                  { $arg = '--capath';        } # alias: ssldiagnose.exe
    #   #if ($arg eq  '--protocol')          { $arg = '--SSL';           } # alias: ssldiagnose.exe
    #
    print "\n";
    _man_head("Alias (regex)         ", "command or option   # used by ...");
    my $fh   = undef;
    if (open($fh, '<:encoding(UTF-8)', $0)) { # need full path for $parent file here
        while(<$fh>) {
            if (m(# alias:)) {
                if (m|^\s*#?if[^/']*.([^/']+).[^/']+.([^/']+).[^#]*#\s*alias:\s*(.*)?|) {
                    my $commt =  $3;
                    my $alias =  $2;
                    my $regex =  $1;
                    # simplify regex for better (human) readability
                    $regex =~ s/^\^//;      # remove leading ^
                    $regex =~ s/^\\//;      # remove leading \ 
                    $regex =~ s/\$$//;      # remove trailing $
                    $regex =~ s/\(\?:/(/g;  # remove ?: in all groups
                    if (length($regex) < 25) {
                        printf("%-25s%-21s# %s\n", $regex, $alias, $commt);
                    } else {
                        # pretty print if regex is to large for first column
                        printf("%s\n", $regex);
                        printf("%-25s%-21s# %s\n", "", $alias, $commt);
                    }
                }
            }
        }
        close($fh);
    }
    _man_foot();
    print "
= Note that - or _ characters used in the option name are not shown,
= they are stripped anyway.
";
    print "\n";
    return;
} # man_alias

sub man_html() {
    #? print complete HTML page for o-saft.pl --help=gen-html
    #? recommended usage:   $0 --no-warning --no-header --help=gen-html
    _man_dbx("man_html() ...");
    _man_http_head();
    _man_html_head();
    _man_html('NAME', 'TODO');
    _man_html_foot();
    return;
} # man_html

sub man_pod() {
    #? print complete HTML page for o-saft.pl --help=gen-pod
    #? recommended usage see at end of this sub
    _man_dbx("man_pod() ...");
    print
'#!/usr/bin/env perldoc
#?
# Generated by o-saft.pl .
# Unfortunatelly the format in @DATA is incomplete,  for example proper  =over
# and corresponding =back  paragraph is missing. It is mandatory arround =item
# paragraphs. However, to avoid tools complaining about that,  =over and =back
# are added to each  =item  to avoid error messages in the viewer tools.
# Hence the additional identations for text following the =item are missing.
# Tested viewers: podviewer, perldoc, pod2usage, tkpod

=pod

=encoding utf8
';

    my $code  = 0;  # 1 if last printed line was `source code' format
    my $empty = 0;  # 1 if last printed line was empty
    while ($_ = shift @DATA) {          # @DATA already looks like POD
        last if m/^(?:=head[1] )?END\s+#/;# very last line in this file
        m/^$/ && do {  ## no critic qw(RegularExpressions::ProhibitFixedStringMatches)
            if ($empty == 0)  { print; $empty++; }  # empty line, but only one
            next;
        };
        s/^(\s*(?:o-saft\.|checkAll|yeast\.).*)/S&$1&/; # dirty hack; adjust with 14 spaces
        s/^ {1,13}//;                   # remove leftmost spaces (they are invalid for POD); 14 and more spaces indicate a line with code or example
        s/^S&\s*([^&]*)&/\t$1/ && do {  # code or example line
            print "\n" if ($empty == 0 && $code == 0);
            print; $empty = 0; $code++; next;   # no more changes
        };
        $code = 0;
        s:'([^']*)':C<$1>:g;            # markup literal text
        s:X&([^&]*)&:L</$1>:g;          # markup references inside help
        s:L&([^&]*)&:L<$1|$1>:g;        # markup other references
        #s:L<[^(]*(\([^\)]*\)\>).*:>:g;  # POD does not like section in link
        s:I&([^&]*)&:I<$1>:g;           # markup commands and options
        s/^([A-Z., -]+)$/B<$1>/;        # bold
        s/^(=item)\s+(.*)/$1 $2/;       # squeeze spaces
        my $line = $_;
        m/^=/ && do {                   # paragraph line
            # each paragraph line must be surrounded by empty lines
            # =item paragraph must be inside =over .. =back
            print "\n"        if ($empty == 0);
            print "=over\n\n" if $line =~ m/^=item/;
            print "$line"     if $line =~ m/^=[hiovbefpc].*/;
            print "\n=back\n" if $line =~ m/^=item/;
            print "\n";
            $empty = 1;
            next;
        };
        print "$line";
        $empty = 0;
    }
    print '
Generated with:

        o-saft.pl --no-warnings --no-header --help=gen-pod > o-saft.pod

=cut

# begin woodoo

# O-Saft documentation is plain text, which is DATA in perl sources. As such,
# it is  not detected as source,  not as comment,  and  not as documentation
# by most tools analyzing the source code.
# Unfortunately, some people solely believe in statistics generated by  magic
# tools. They use such statistics to measure for example code quality without
# looking themself at the code.
# Hence the purpose of this file is to provide real comment and documentation
# lines from our documentation in format of the used programming language.
# Hopefully, if these people read this, they change the workflow (means: they
# also review the source code) or adapt their conclusions having in mind that
# statistics can be manipulated in many ways. Here we go ...
# 
# Disclaimer: No offence meant anyhow, neither against any analyzing tool nor
# against anyone using them. It is just a reminder to use the tools and their
# results in a wise manner. Measuring quality is more than just automatically
# generated statistics!

# end woodoo

';
    return;
} # man_pod

sub man_cgi() {
    #? print complete HTML page for o-saft.pl used as CGI
    #? recommended usage:   $0 --no-warning --no-header --help=gen-cgi
    #?    o-saft.cgi?--cgi=&--usr&--no-warning&--no-header=&--cmd=html
    _man_dbx("man_cgi() ...");
    my $cgi = _man_usr_value('user-action') || _man_usr_value('usr-action') || "/cgi-bin/o-saft.cgi"; # get action from --usr-action= or set to default
    _man_http_head();
    _man_html_head();
print << "EoHTML";
 <a href="$cgi?--cgi&--help" target=_help ><button value="" />help</button></a>&#160;&#160;
 <a href="$cgi?--cgi&--help=command" target=_help ><button value="" />commands</button></a>&#160;&#160;
 <a href="$cgi?--cgi&--help=checks"  target=_help ><button value="" />checks</button></a>&#160;&#160;
 <a href="$cgi?--cgi&--help=score"   target=_help ><button value="" />score</button></a>&#160;&#160;
 <a href="$cgi?--cgi&--help=regex"   target=_help ><button value="" />regex</button></a>&#160;&#160;
 <a href="$cgi?--cgi&--abbr" target=_help ><button value="" />Glossar</button></a>&#160;&#160;
 <a href="$cgi?--cgi&--todo" target=_help ><button value="" />ToDo</button></a><br>
 <form action="$cgi" method=GET >
  <input  type=hidden name="--cgi" value="" >
  <fieldset>
EoHTML

    print _man_html_text('host');
    print _man_html_text('port');
print << "EoHTML";
    <div id=a style="display:block;">
        <button class=r onclick="t(d('a'));t(d('b'));return false;">Full GUI</button><br>
EoHTML
    foreach my $key (qw(cmd cmd cmd cmd)) { print _man_html_cmd($key); }
    print _man_html_br();
    print _man_html_span('check cipher quick info info--v vulns dump check_sni help http list libversion sizes s_client version quit sigkey bsi ev cipherraw'); # similar to @{$cfg{'cmd-intern'}}
    foreach my $key (qw(sslv3 tlsv1 tlsv11 tlsv12 tlsv13 sslv2null BR
                     no-sni sni no-http http BR
                     no-dns dns no-cert BR
                     no-openssl openssl force-openssl  BR
                     no-header  header  short showhost BR
                     enabled disabled BR
                     v v trace trace traceCMD traceKEY BR
                 )) {
        if ($key eq 'BR') { print _man_html_br(); next; }
        print _man_html_cbox($key);
    }
    foreach my $key (qw(separator timeout legacy)) { print _man_html_text($key); }
    print _man_html_br();
    print _man_html_span('cnark sslaudit sslcipher ssldiagnos sslscan ssltest ssltest-g sslyze testsslserver thcsslcheck openssl simple full compact quick'); # similar to @{$cfg{'legacys'}}
    print _man_html_text("format");
    print _man_html_span('csv html json ssv tab xml fullxml raw hex'); # milar to @{$cfg{'formats'}}:
    print << "EoHTML";
        <br>
    </div>
    <div id=b style="display:none;">
        <button class=r onclick="d('a').display='block';d('b').display='none';return false;">Simple GUI</button><br>
        <input type=text     name=--cmds size=55 />&#160;
EoHTML

    _man_html("COMMANDS", 'LAZY');
    print << "EoHTML";
</p>
    </div>
        <input type=submit value="go" />
  </fieldset>
 </form>
EoHTML
    _man_html_foot();
    return;
} # man_cgi

sub man_wiki($) {
    #? print documentation for o-saft.pl in mediawiki format (to be used at owasp.org)
    #? recommended usage:   $0 --no-warning --no-header --help=gen-wiki
    my $mode =  shift;
        # currently only mode=colon is implemented to print  :*  instead of *
        # Up to VERSION 15.12.15 list items * and ** where printed without
        # leading : (colon). Some versions of mediawiki did not support :*
        # so we can switch this behavior now.
    _man_dbx("man_wiki($mode) ...");
    my $key = "";
    # 1. generate wiki page header
    print "
==O-Saft==
This is O-Saft's documentation as you get with:
 o-saft.pl --help
<small>On Windows following must be used
 o-saft.pl --help --v
</small>

__TOC__ <!-- autonumbering is ugly here, but can only be switched of by changing MediaWiki:Common.css -->
<!-- position left is no good as the list is too big and then overlaps some texts
{|align=right
 |<div>__TOC__</div>
 |}
-->

[[Category:OWASP Project]]  [[Category:OWASP_Builders]]  [[Category:OWASP_Defenders]]  [[Category:OWASP_Tool]]  [[Category:SSL]]  [[Category:Test]]
----
";
    # 2. generate wiki page content
    #    extract from herein and convert POD syntax to mediawiki syntax
    while ($_ = shift @DATA) {
        last if/^=head1 TODO/;
        s/^=head1 (.*)/====$1====/;
        s/^=head2 (.*)/=====$1=====/;
        s/^=head3 (.*)/======$1======/;
        s/^=item (\*\* .*)/$1/;         # list item, second level
        s/^=item (\* .*)/$1/;           # list item, first level
        s/^=[^= ]+ *//;                 # remove remaining markup and leading spaces
        print, next if/^=/;             # no more changes in header lines
        s!'([^']*)'!<code>$1</code>!g;  # markup examples
        s/^S&([^&]*)&/  $1/ && do { print; next; }; # code or example line; no more changes
        s/X&([^&]*)&/[[#$1|$1]]/g;      # markup references inside help
        s/L&([^&]*)&/\'\'$1\'\'/g;      # markup other references
        s/I&([^&]*)&/\'\'$1\'\'/g;      # markup commands and options
        s/^ +//;                        # remove leftmost spaces (they are useless in wiki)
        if ($mode eq 'colon') {
            s/^([^=].*)/:$1/;           # ident all lines for better readability
        } else {
            s/^([^=*].*)/:$1/;          # ...
        }
        s/^:?\s*($parent)/  $1/;        # myself becomes wiki code line
        s/^:\s+$/\n/;                   # remove empty lines
        print;
    }
    # 2. generate wiki page footer
    print "
----
<small>
Content of this wiki page generated with:
 $parent --no-warning --no-header --help=gen-wiki
</small>
";
    return;
} # man_wiki

sub man_toc($) {
    #? print help table of content
    my $typ     = lc(shift) || "";      # || to avoid uninitialized value
    _man_dbx("man_toc() ..");
    foreach my $txt (grep{/^=head. /} @DATA) {  # note: @DATA is in POD format
        next if ($txt !~ m/^=head/);
        next if ($txt =~ m/^=head. *END/);  # skip last line
        if ($typ =~ m/cfg/) {
            $txt =~ s/^=head1 *(.*)/{print "--help=$1\n"}/e;
        } else {
            # print =head1 and =head2
            # just =head1 is lame, =head1 and =head2 and =head3 is too much
            $txt =~ s/^=head([12]) *(.*)/{print "  " x $1, $2,"\n"}/e; # use number from =head as ident
        }
    }
    return;
} # man_toc

sub man_help($) {
    #? print program's help
    my $label   = lc(shift) || "";      # || to avoid uninitialized value
    my $anf     = uc($label);
    my $end     = "[A-Z]";
    _man_dbx("man_help($anf, $end) ...");
    # no special help, print full one or parts of it
    my $txt = join ("", @DATA);
    if ((grep{/^--v/} @ARGV) > 1) {     # with --v --v
        print scalar reverse "\n\n$egg";
        return;
    }
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
        print $txt;
    }
    if ($label =~ m/^todo/i)    {
        print "\n  NOT YET IMPLEMENTED\n";
        foreach my $label (sort keys %checks) {
            next if (_is_member($label, \@{$cfg{'cmd-NOT_YET'}}) <= 0);
            print "        $label\t- " . $checks{$label}->{txt} . "\n";
        }
    }
    return;
} # man_help

sub printhelp($) { ## no critic qw(Subroutines::ProhibitExcessComplexity)
    #? simple dispatcher for various help requests
    #  NOTE critic: as said: *this code is a simple dispatcher*, that's it
    my $hlp = shift;
    _man_dbx("printhelp($hlp) ...");
    # Note: some lower case strings are special
    man_help('NAME'),           return if ($hlp =~ /^$/);           ## no critic qw(RegularExpressions::ProhibitFixedStringMatches)
    man_help('TODO'),           return if ($hlp =~ /^todo$/i);      ## no critic qw(RegularExpressions::ProhibitFixedStringMatches)
    man_help('KNOWN PROBLEMS'), return if ($hlp =~ /^(err(?:or)?|warn(?:ing)?|problem)s?$/i);
    if ($hlp =~ /^faq/i) {
        man_help('KNOWN PROBLEMS');
        man_help('LIMITATIONS');
        return
    }
    man_help($hlp),             return if ($hlp =~ /^(?:CHECKS?|CUSTOM)$/); # not case-sensitive!
        # NOTE: bad design, as we have headlines in the documentation which
        #       are also used as spezial meaning (see below). In particular
        #       CHECKS  is a  headline for a section  in the documentation,
        #       while  checks  is used to print the labels of performed all
        #       checks. Workaround is to treat all-uppercase words as head-
        #       line of a section and anything else as special meaning.
        # However, note that  --help=chec  already behaves the  same way as
        # --help=CHECKS  while  --help=check  prints the labels. Means that
        # this special condition (match CHECKS) is just for commodity.
    man_toc($1),                return if ($hlp =~ /^((?:toc|content)(?:.cfg)?)/i);
    man_html(),                 return if ($hlp =~ /^(gen-)?html$/);
    man_wiki('colon'),          return if ($hlp =~ /^(gen-)?wiki$/);
    man_pod(),                  return if ($hlp =~ /^(gen-)?pod$/i);
    man_cgi(),                  return if ($hlp =~ /^(gen-)?cgi$/i);
        # Note: gen-cgi is called from within parent's BEGIN and hence
        # causes some   Use of uninitialized value within %cfg 
        # when called as  gen-CGI  it will not be called from within
        # BEGIN and hence %cfg is defined and will not result in warnings
    man_alias(),                return if ($hlp =~ /^alias(es)?$/);
    man_commands(),             return if ($hlp =~ /^commands?$/);
    # anything below requires data defined in parent
    man_table('rfc'),           return if ($hlp =~ /^rfcs?$/);
    man_table('abbr'),          return if ($hlp =~ /^(abbr|abk|glossar)$/); ## no critic qw(RegularExpressions::ProhibitFixedStringMatches)
    man_table(lc($1)),          return if ($hlp =~ /^(intern|compl(?:iance)?)s?$/i);
    man_table(lc($1)),          return if ($hlp =~ /^(check|data|hint|text|range|regex|score|ourstr)s?$/i);
    man_table('cfg_'.lc($1)),   return if ($hlp =~ /^(check|data|hint|text|range|regex|score|ourstr)s?[_-]?cfg$/i);
    man_table('cfg_'.lc($1)),   return if ($hlp =~ /^cfg[_-]?(check|data|hint|text|range|regex|score|ourstr)s?$/i);
        # we allow:  text-cfg, text_cfg, cfg-text and cfg_text so that
        # we can simply switch from  --help=text  and/or  --cfg_text=*
    if ($hlp =~ /^cmds?$/i)     { # print program's commands
        print "# $parent commands:\t+"     . join(" +", @{$cfg{'commands'}});
        return;
    }
    if ($hlp =~ /^legacys?$/i)  { # print program's legacy options
        print "# $parent legacy values:\t" . join(" ",  @{$cfg{'legacys'}});
        return;
    }
    if ($hlp =~ m/^opts?$/i)    { # print program's options
        my @txt  = grep{/^=head. (General|Option|--)/} @DATA;   # grep options only
        foreach my $line (@txt) { $line =~ s/^=head. *//}       # remove leading markup
        my($end) = grep{$txt[$_] =~ /^Options vs./} 0..$#txt;   # find end of OPTIONS section
        print join("", "OPTIONS\n", splice(@txt, 0, $end));     # print anything before end
        return;
    }
    if ($hlp =~ m/^Program.?Code$/i) { # print Program Code description, is not yet public
        # quick&dirty hack, may be improved in future ...
        my $skip = 1;
        my $fh   = undef;
        if (open($fh, '<:encoding(UTF-8)', $wer)) {
            while (<$fh>) {
                $skip = 0 if (/^#\s+Program Code/);
                next if ($skip > 0);
                last if (($skip == 0) and (/^$/));  ## no critic qw(RegularExpressions::ProhibitFixedStringMatches)
                print;
            }
            close($fh);
        }
        return;
    }
    # nothing matched so far, try to find special section and only print that
    _man_dbx("printhelp: " . uc($hlp));
    man_help(uc($hlp));
    return;
} # printhelp

sub o_saft_man_done() {};       # dummy to check successful include
## PACKAGE }

printhelp($ARGV[0]) unless (defined caller);

1;

#| documentation
#| -------------------------------------
# All documentation is in plain ASCII format.
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
#       which referes to sub-titles, it must be used to properly markup internal
#       links to sub-sections if the title is not written in all upper case.
#
#   All head lines for sections (see TITLE above) are preceeded by 2 empty lines.
#   All head lines for commands and options should contain just this command
#   or option, aliases should be written in their own line (to avoid confusion
#   in some other parsers, like Tcl).
#   List items should be followed by an empty line.
#
# Special markups for o-saft.tcl:
#   - the sub-titles in the COMMANDS and OPTIONS sections must look like:
#       Commands for whatever text
#       Commands to whatever text
#       Options for whatever text
#     means that the prefixes  "Commands for"  and  "Options for"  are used to
#     identify groups of commands and options. If a sub-title does not start
#     with these prefixes, all following commands and options are ignored.
#
# Initilly the documentation was done using perl's doc format (perldoc, POD).
# The advantage having a well formated output available on various platforms,
# resulted in more difficult efforts extracting information from there.
# In particular following problems occoured:
#   - perldoc is not available on all platforms by default
#   - POD is picky when text lines start with a whitespace
#   - programatically extracting data from POD requires additional substitutes
#   - POD is slow
#
# Changing POD to plain ASCII
#   equal source code: lines or kBytes in o-saft-usr.pm vs. o-saft-man.pm
#     Description              POD ASCII           %    File
#   -------------------------+----+-------------+------+----------
#   * reduced doc. text:      3110  2656 lines     85%  o-saft.pl
#   * reduced doc. text:      86.9  85.5 kBytes    98%  o-saft.pl
#   * reduced source code:     122    21 lines     17%  o-saft.pl
#   * reduced source code:     4.4   1.0 kBytes    23%  o-saft.pl
#   * improved performance:    2.7  0.02 seconds 0.75%  o-saft.pl
#   -------------------------+----+-------------+------+----------

__END__
__DATA__


NAME

        O-Saft - OWASP SSL advanced forensic tool
                 OWASP SSL audit for testers


DESCRIPTION

        This tools lists  information  about remote target's  SSL certificate
        and tests the remote target according given list of ciphers.

        Note:  Throughout this description  '$0'  is used as an alias for the
        program name  'o-saft.pl'.


SYNOPSIS

        $0 [COMMANDS ..] [OPTIONS ..] target [target target ...]

        where  [COMMANDS]  and  [OPTIONS]  are described below  and target is
        a hostname either as full qualified domain name or as IP address.
        Multiple commands and targets may be combined.

        All  commands  and  options  can also be specified in a  rc-file, see
        RC-FILE  below.


QUICKSTART

        Before going into  a detailed description  of the  purpose and usage,
        here are some examples of the most common use cases:

        * Show supported (enabled) ciphers of target:
          $0 +cipher --enabled example.tld

        * Show supported (enabled) ciphers with their DH parameters:
          $0 +cipher-dh example.tld

        * Test all ciphers, even if not supported by local SSL implementation:
          $0 +cipherall example.tld

        * Show details of certificate and connection of target:
          $0 +info example.tld

        * Check certificate, ciphers and SSL connection of target:
          $0 +check example.tld

        * Check connection to target for vulnerabilities:
          $0 +vulns example.tld

        * Check for all known ciphers (independant of SSL library):
          $0 +cipherall example.tld --range=full
          checkAllCiphers.pl example.tld
          checkAllCiphers.pl example.tld --range=full --v

        * Get the certificate's Common Name for a bunch of servers:
          $0 +cn example.tld some.tld other.tld

        * List more usage examples
          $0 --help=examples

        * List all available commands:
          $0 --help=commands

        * Get table of contents for complete help
          $0 --help=toc

        * Show just one section, for example SECURITY, from help
          $0 --help=SECURITY

        * Start the simple GUI
          o-saft.tcl

        For more specialised test cases, refer to the  COMMANDS  and  OPTIONS 
        sections below. For more examples please refer to  EXAMPLES  section.

        For more details, please see  X&Requirements&  and  INSTALLATION  below.


WHY?

        Why a new tool for checking SSL security and configuration  when there
        are already a dozen or more such good tools in existence (circa 2012)?

        Unique features:
          * working in closed environments, i.e. without internet connection
          * checking availability of ciphers independent of installed library
          * checking for all possible ciphers (up to 65535 per SSL protocol)
          * mainly same results on all platforms.

        Currently available tools suffer from some or all of following issues:
          * lack of tests of unusual SSL certificate configurations
          * may return different results for the same checks on given target
          * missing tests for modern SSL/TLS functionality
          * missing tests for specific, known SSL/TLS vulnerabilities
          * no support for newer, advanced, features e.g. CRL, OCSP, EV
          * limited capability to create your own customised tests

        Other  reasons or problems  are that other tools are either binary or
        use additional binaries and hence not portable to other platforms.

        In contrast to (all?) most other tools, including  openssl(1), it can
        be used to "ask simple questions" like "does target support STS" just
        by calling:
          $0 +hsts_sts example.tld

        For more, please see  EXAMPLES  section below.


SECURITY

        This tool is designed to be used by people doing security or forensic
        analyses. Hence no malicious input is expected.

        There are no special security checks implemented. Some parameters are
        roughly sanatised according unwanted characters.  In particular there
        are no checks according any kind of code injection.

        Care should be taken, when additional tools and modules are installed
        as described in  INSTALLATION  below.  In particular  we recommend to
        do such installations into directoies specially prepared for use with
        $0 . No other tools of your system should use these installations
        i.e. by accident or because your environment variables point to them.

        Note that compilation and installation of additional tools  (openssl, 
        Net::SSLeay, etc.) uses known insecure configurations and features!
        This is essential to make $0 able to check for such insecurities.

        It is  highly recommended to do these installations and use the tools
        on a separate testing system.

        DO NOT USE THESE INSTALLATIONS ON PRODUCTIVE SYTEMS.


TECHNICAL INFORMATION

        It is important to understand, which provided information is based on
        data returned by underlaying (used) libraries and the information 
        computed directly.

    openssl, libssl, libcrypto

        In general the tool uses perl's  Net::SSLeay(1)  module  which itself
        is based on libssl and/or libssleay library of the operating system.
        It's possible to use other versions of these libraries, see options:
          * --exe-path=PATH --exe=PATH
          * --lib-path=PATH --lib=PATH
          * --envlibvar=NAME

        The external  openssl(1)  is called to extract  some information from
        its output.  The version of openssl can be controlled  with following
        options:
          * --openssl=TOOL
          * --no-openssl
          * --force-openssl
          * --exe-path=PATH --exe=PATH

        Above applies to all commands except  +cipherall  which uses no other
        libraries.

        OpenSSL is recommended to be used for libssl and libcrypto.  Versions
        0.9.8k to 1.0.2e (Jan. 2016) are known to work. However, versions be-
        for 1.0.0 may not provide all informations.
        LibreSSL is not recommended, because  some functionallity  considered
        insecure, has been removed.
        For more details, please see  INSTALLATION  below.


    Certificates and CA

        All checks according the validity of the certificate chain  are based
        on the root CAs installed on the system. NOTE that Net::SSLeay(1) and
        openssl(1)  may have their own rules where to find the root CAs.
        Please refer to the documentation on your system for these tools.
        However, there are folloing options to tweak these rules:
          * --ca-file=FILE
          * --ca-path=DIR
          * --ca-depth=INT

    Commands and options

        All arguments  starting with  '+'  are considered  COMMANDS  for this
        tool. All arguments starting with  '--'  are considered  OPTIONS  for
        this tool.

        Reading any data from STDIN or here-documents is not yet supported.
        It's reserved for future use.

    Environment variables

        Following environment variables are incorporated:
          * LD_LIBRARY_PATH - used and extended with definitions from options
          * OPENSSL         - if set, full path to openssl executable
          * OPENSSL_CONF    - if set, full path to openssl's openssl.cnf or
                              directory where to find openssl.cnf
#         * OPENSSL_FIPS    - 
#         * OPENSSL_ENGINES -
#         * OPENSSL_ALLOW_PROXY
#         * OPENSSL_ALLOW_PROXY_CERTS


    Requirements

        For checking all ciphers and all protocols with  +cipherall  command,
        just perl (5.x) without any modules is required.

        For  +info  and  +check  (and all related) commands,  perl (5.x) with
        following modules (minimal version) is required:

          * IO              1.25 (2011)
          * IO::Socket::SSL 1.37 (2011)
          * IO::Socket::SSL 1.90 (2013)
          * Net::DNS        0.66 (2011)
          * Net::SSLeay     1.49 (2012)

        However, it is recommended to use the most recent version of the mod-
        ules which then gives more accurate results and less warnings. If the
        modules are missing, they can be installed i.e. with:

              cpan Net::SSLeay

        Note: if you want to use advanced features of openssl or Net::SSLeay,
        please see  INSTALLTION  section how to compile and install the tools
        fully customized.

        Also an openssl executable should be available, but is not mandatory.

        For checking DH parameters of ciphers, openssl 1.0.2  or newer should
        be available. If an older version of openssl is found, we try hard to
        extract  the DH parameters from the  data returned by the server, see
        +cipher-dh  command.


RESULTS

        All output is designed to be easily parsed by postprocessors.  Please
        see  OUTPUT  section below for details.

        For the results,  we have to distinguish  those  returned by  +cipher
        command  and those from  all other tests and checks like   +check  or
        +info  command.

      +cipher

          The cipher checks will return  one line for each  tested cipher. It
          contains at least the cipher name,  'yes'  or  'no'  whether  it is
          supported or not, and a security qualification. It may look like:
              AES256-SHA       yes    HIGH
              NULL-SHA         no     weak

          Depending on the used  --legacy=*  option the format may differ and
          also contain more information.  For details see  --legacy=*  option
          below.

          The text for security qualifications are (mainly) those returned by
          openssl (version 1.0.1): LOW, MEDIUM, HIGH and WEAK.
          The same texts, but with all lower case characters, are used if the
          qualification was adapted herein. Following rules for adjusting the
          qualification were used:

            * weak:
              ** all *NULL* ciphers
              ** all *RC2* and  *RC4*  ciphers
              ** all *EXPORT*  ciphers
              ** all *anon* (aka ADH aka DHA) ciphers
            * low:
              ** all *CBC*  ciphers
            * high:
              ** all *CBC3* (aka 3DES) ciphers
              ** all *AES(128|256)* ciphers
              ** all *CAMELLIA* ciphers

      +check

          These tests return a line with  a label  describing the test  and a
          test result for it. The  idea is to report  'yes'  if the result is
          considered "secure"  otherwise report  'no'  followed by the reason
          why it's considered insecure. Example of a check considered secure:
              Label of the performed check:           yes

          Example of a check considered insecure:
              Label of the performed check:           no (reason why)

          Note  that there are tests where the results  appear confusing when
          first viewed, like for www.wi.ld:
              Certificate is valid according given hostname:  no (*.wi.ld)
              Certificate's wildcard does not match hostname: yes

          This can for example occur with:
              Certificate Common Name:                *.wi.ld
              Certificate Subject's Alternate Names:  DNS:www.wi.ld

          Please check the result with the  +info  command also to  verify if
          the check sounds reasonable.

      +info

          The test result contains detailed information. The labels there are
          mainly the same as for the  +check  command.


COMMANDS

        There are commands for various tests according the  SSL connection to
        the target, the targets certificate and the used ciphers.

        All commands are preceded by a  '+'  to easily distinguish from other
        arguments and options. However, some --OPTIONS options are treated as
        commands for historical reason or compatibility to other programs.

        The most important commands are (in alphabetical order):
          +check +cipher +info +http +list +quick +sni +sni_check +version

        A list of all available commands will be printed with:
          $0 --help=cmd

        The description of all other commands will be printed with:
          $0 --header --help=commands

        The summary and internal commands return requested information or the
        results of checks. These are described below.

        Note that some commands may be a combination of other commands, see:
          $0 --header --help=intern

        The following sub-sections only describe the commands,  which do more
        than giving a simple information from the target.  All other commands
        can be listed with:
          $0 --header --help=commands

        The final sub-sections  X&Notes about commands&  describes some notes
        about special commands and related commands.
        

    Commands for information about this tool

        All these commands will exit after execution (cannot be used together
        with other commands).

      +ciphers

          Show ciphers offered by local SSL implementation.

          This commands prints the ciphers in a format like "openssl ciphers"
          does. It also accepts the  -v  and  -V  option. The  --legacy=TYPE 
          option can be used as described for  +list  command.
          Use  +list  command for more information according ciphers.

      +list

          Show all ciphers supported by this tool. This includes cryptogrphic
          details of the cipher and some internal details about the rating.

          In contrast to the  +ciphers  command,  +list  uses  TAB characters
          instead of spaces to seperate columns.  It also prints table header
          lines by default.

          Different output formats are used for the  --legacy  option:
            * --legacy=simple   tabular output of cipher values
            * --legacy=full     as --legacy=simple but more data
            * --legacy=openssl  output like with +ciphers command
            * --legacy=ssltest  output like "ssltest --list"

#          Use  --v  option to show more details.
# seit 15.01.07 nicht mehr benutzt

      +VERSION

          Just show version and exit.

      +version

          Show version information for both the program and the  Perl modules
          that it uses, then exit.

          Use  --v  option to show more details.

      +libversion

          Show version of openssl.

      +quit

          Show internal data and exit, used for debugging only.

    Commands to check SSL details
#
#       Check for SSL connection in  SNI mode and if given  FQDN  matches
#       certificate's subject.

        Following (summary and internal) commands are simply a shortcut for a
        list of other commands. For details of the list use:
              $0 --help=intern

      +check

          Check the SSL connection for security issues. This is the same as:
            +info +cipher +sizes --sslv2 --sslv3 --tlsv1 --tlsv11 --tlsv12
          but also gives some kind of scoring for security issues if any.
#
#         The rating is mainly based on the information given in
#           http://ssllabs.com/.....

      +http

          Perform HTTP checks (like STS, redirects etc.).

      +info

          Overview of most important details of the SSL connection.

          Use  --v  option to show details also, which span multiple lines.

      +info--v

          Overview of all details of the SSL connection. It is a shortcut for
          all commands listed below but not including  +cipher.

          This command is intended for debugging as it prints some details of
          the used  Net::SSLinfo  module.

      +quick

          Quick overview of checks. Implies  --enabled  and  --short.

      +pfs

          Check if servers offers ciphers with prefect forward secrecy (PFS).

      +sts
      +hsts

          Various checks according STS HTTP header.
          This option implies  --http,  means that  --no-http is ignored.

      +sni

          Check for Server Name Indication (SNI) usage.

      +sni_check
      +check_sni

          Check for Server Name Indication (SNI) usage  and  validity  of all
          names (CN, subjectAltName, FQDN, etc.).

      +bsi

          Various checks according BSI TR-02102-2 and TR-03116-4 compliance.

      +ev

          Various checks according certificate's extended Validation (EV).

          Hint: use option  --v --v  to get information about failed checks.

      +sizes

          Check length, size and count of some values in the certificate.

      +s_client

          Dump data retrieved from  "openssl s_client ..."  call. This should
          be used for debugging only.
          It can be used just like openssl itself, for example:
              openssl s_client -connect host:443 -no_sslv2

      +dump

          Dumps internal data for SSL connection and target certificate. This
          is mainly for debugging and  should not be used together with other
          commands (except +cipher).
          Each key-value pair is enclosed in  #{  and  #} .

          Using  --trace --trace  dumps data of  Net::SSLinfo  too.

      +exec

          Command used internally when requested to use other libraries.
          This command should not be used directly.


    Commands to test target's ciphers

      +cipher

          Check target for ciphers,  either all ciphers, or ciphers specified
          with  --cipher=*  option.

          Note that ciphers not supported by the local SSL implementation are
          not checked by default, use  +cipherall  command for that.

# other names: +cipherall +allciphers +rawciphers
      +cipherall
      +cipherraw

          Check target for all possible ciphers.
          Does not depend on local SSL implementation.

          In contrast to  +cipher  this command has some options to tweak the
          cipher tests, connection results and some strange behaviours of the
          target. See  X&Options for cipherall command&  for details.

      +cipher-SSL

          Get default cipher for protocol SSL.

          * 'SSL'       can be any of:
                        sslv2, sslv3, tls1, tls11, tls12, tls13, dtls1

    Commands to test SSL connection to target

        Please see:
          $0 --help=commands

    Commands to show details of the target's certificate

        Please see:
          $0 --help=commands

    Notes about commands

      +extensions vs. +tlsextensions

          +extensions  shows the "Certificate extensions" and  +tlsextensions
          will show the TLS protocol extensions.
          Use  +tlsextdebug  to show more informations about the TLS protocol
          extensions.

      +http2 +spdy +spdy3 +spdy31 +spdy4 +prots

          These commands are just an alias for the  +protocols  command.


OPTIONS

        All options are written in lowercase. Words written in all capital in
        the description here is text provided by the user.

    Options for help and documentation

      --h

      --help

          WYSIWYG

      --help=cmd

          Show available commands; short form.

      --help=commands

          Show available commands with short description.

      --help=opt

          Show available options; short form.

      --help=options

          Show available options with their description.

      --help=checks

          Show available checks.

      --help=check-cfg
      --help=cfg-check

          Show texts used as labels in output for checks (see  +check)  ready
          for use in  RC-FILE  or as option.

      --help=data

          Show available informations.

      --help=data-cfg
      --help=cfg-data

          Show texts used  as labels in output for  data  (see  +info)  ready
          for use in  RC-FILE  or as option.

      --help=hint

          Show texts used in hint messages.

      --help=hint-cfg
      --help=cfg-hint

          Show texts used in hint messages ready for use in  RC-FILE  or as
          option.

      --help=text

          Show texts used in various messages.

      --help=text-cfg
      --help=cfg-text

          Show texts used in various messages ready for use in  RC-FILE  or
          as option.

      --help=legacy

          Show possible legacy formats (used as value in  --legacy=TOOL).

      --help=compliance

          Show available compliance checks.

      --help=intern

          Show internal commands.

      --help=alias

          Show alias for commands and options.

      --help=range

          Show list of cipherranges (see  --cipherrange=RANGE).

      --help=score

          Show score value for each check.
          Value is printed in format to be used for  --cfg-score=KEY=SCORE.

          Note that the  sequence  of options  is important.  Use the options
          --trace  and/or  --cfg-score=KEY=SCORE  before  --help=score.

      --help=toc
      --help=content

          Show headlines from help text. Useful to get an overview.

      --help=SECTION

          Show  <SECTION>  from documentation, see  --help=toc  for a list.
          Example:
              $0 --help=EXAMPLES

      --help=ourstr

          Show regular expressions to match our own strings used in output.

      --help=regex

          Show regular expressions used internally.

      --help=gen-html

          Print documentation in HTML format.

      --help=gen-wiki

          Print documentation in mediawiki format.

      --help=gen-cgi

          Print documentation in format to be used for CGI.

      --help=error
      --help=warning
      --help=problem

          Show  KNOWN PROBLEMS  section with  description of known  error and
          warning messages.

      --help=faq

          Show  KNOWN PROBLEMS  and  LIMITATIONS  section.

      --help=glossar

          Show common abbreviation used in the world of security.

      --help=todo

          Show known problems and bugs.

      --help=program.code

          For developers.

    Options for all commands (general)

      --no-rc

          Do not read  RC-FILE.

      --dns

          Do DNS lookups to map given hostname to IP, do a reverse lookup.

      --no-dns

          Do not make DNS lookups.
          Note  that the corresponding IP and reverse hostname may be missing
          in some messages then.

      --host=HOST

          Specify HOST as target to be checked. Legacy option.

      --port=PORT

          Specify PORT of target to be used. Legacy option.

      --host=HOST and --port=PORT and HOST:PORT and HOST

          When giving more than one HOST argument,  the sequence of the given
          HOST argument and the given  --port=PORT  and the given --host=HOST
          options are important.
          The rule how ports and hosts are mapped is as follows:

            HOST:PORT arguments are used as is (connection to HOST on PORT)
            only HOST is given, then previous specified  --port=PORT  is used

          Note that URLs are treated as HOST:PORT, if they contain a port.
          Example:
              $0 +cmd host-1 --port 23 host-2 host-3:42 host-4

          will connect to:
            * host-1:443
            * host-2:23
            * host-3:42
            * host-4:23

      --proxyhost=PROXYHOST --proxy=PROXYHOST:PROXYPORT

          Make all connection to target using PROXYHOST.

          Also possible is: --proxy=PROXYUSER:PROXYPASS@PROXYHOST:PROXYPORT

      --proxyport=PROXYPORT

          Make all connection to target using PROXYHOST:PROXYPORT.

      --proxyuser=PROXYUSER

          Specify username for proxy authentication.

      --proxypass=PROXYPASS

          Specify password for proxy authentication.

      --starttls

          Use 'STARTTLS' command to start a TLS connection via SMTP.
          This option is a shortcut for  --starttls=SMTP .

      --starttls=SMTP
      --starttls=PROT

          Use 'STARTTLS' command to start a TLS connection via protocol. PORT
          PORT may be any of: 'SMTP', 'IMAP', 'IMAP2', 'POP3', 'FTPS', 'RDP',
          'LDAP' or 'XMPP'

          For  --starttls=SMTP  see  --dns-mx  also to use MX records instead
          of host

      --starttls-delay=SEC

          Number of seconds to wait before sending a packet, to slow down the
          'STARTTLS' requests. Default is 0.
          This may prevent blocking of requests by the target due to too much
          or too fast connections.
          Note:  In this case there is an automatic suspension and retry with
          a longer delay.

      --cgi
      --cgi-exec

          Internal use for CGI mode only.

    Options for SSL tool

      --s_client

          Use  "openssl s_slient ..."  call to retrieve more information from
          the SSL connection.  This is disabled by default on Windows because
          of performance problems. Without this option (default on Windows !)
          following informations are missing on Windows:
              compression, expansion, renegotiation, resumption,
              selfsigned, verify, chain, protocols, DH parameters

          See  Net::SSLinfo  for details.

          If used together with  --trace, s_client  data will also be printed
          in debug output of  Net::SSLinfo.

      --no-openssl

          Do not use external "openssl"  tool to retrieve information. Use of
          "openssl" is disabled by default on Windows.
          Note that this results in some missing informations, see above.

      --openssl=TOOL

          'TOOL'        can be a path to openssl executable; default: openssl
#         * ssleay:     use installed Net::SSLeay library for perl
#         * x86_32:     use  ** NOT YET IMPLEMENTED **
#         * x86_64:     use  ** NOT YET IMPLEMENTED **
#         * x86Mac:     use  ** NOT YET IMPLEMENTED **
#         * arch:       use  ** NOT YET IMPLEMENTED **

      --openssl-cnf=FILE --openssl-conf=FILE

          'FILE'        path of directory or full path of openssl.cnf

          If set, environment variable OPENSSL_CONF will be set to given path
          (or file) when openssl(1) is started. Please see openssl's man page
          for details about specifying alternate  openssl.cnf  files.

      --force-openssl

          Use openssl to check for supported ciphers;  default: IO::Socket(1)

          This option forces to use  "openssl s_slient -connect CIPHER .." to
          check if a cipher is supported by the remote target. This is useful
          if the  --lib=PATH  option doesn't work (for example due to changes
          of the API or other incompatibilities).

      --exe-path=PATH
      --exe=PATH

          'PATH'        is a full path where to find openssl.

      --lib-path=PATH
      --lib=PATH

          'PATH'        is a full path where to find libssl.so and libcrypto.so

          See X&HACKER's INFO& below for a detailed description how it works.

      --envlibvar=NAME

          'NAME'  is the name of a environment variable containing additional
          paths for searching dynamic shared libraries.
          Default is LD_LIBRARY_PATH.

          Check your system for the proper name, i.e.:
              DYLD_LIBRARY_PATH, LIBPATH, RPATH, SHLIB_PATH.

      --ssl-lazy

          I.g. this tools tries to identify available functionality according
          SSL versions from the underlaying libraries.  Unsupported  versions
          are then disables and a warning is shown.
          Unfortunately some libraries have  not implemented all functions to
          check availability of a specific SSL version, which then results in
          a compile error. 

          This option disables the strict check of availability.
          If the underlaying library doesn't support the required SSL version
          at all, following error may occour:
              Can't locate auto/Net/SSLeay/CTX_v2_new.al in @INC ...

          See X&Note on SSL versions&  for a general note about SSL versions.
          A more detailled description of the problem and how Net::SSLeay be-
          haves, can be found in the source of  $0 ,
          see section starting at
              #| check for supported SSL versions


# following missing on owasp.org 'cause still not fully implemented
      --call=METHOD

          'METHOD'      method to be used for specific functionality

          Available methods:
          * info-socket         use internal socket to retrieve information
          * info-openssl        use external openssl to retrieve information
          * info-user           use usr_getinfo() to retrieve information
          * cipher-socket       use internal socket to ckeck for ciphers
          * cipher-openssl      use external openssl to ckeck for ciphers
          * cipher-user         use usr_getciphers() to ckeck for ciphers
  
          Method names starting with:
          * info-
            are responsible to retrieve information  about the SSL connection
            and the target certificate (i.e. what the +info command provides)
          * cipher-
            are responsible to connect to the target  and test if it supports
            the specified ciphers  (i.e. what the  +cipher  command provides)
          * check-
            are responsible for performing the checks (i.e. what's shown with
            the  +check  command)
          * score-
            are responsible to compute  the score based on check results
 
          The second part of the name denotes which kind of method to call:
          * socket      the internal functionality with sockets is used
          * openssl     the exteranl openssl executable is used
          * user        the external special function, as specified in user's
                        o-saft-usr.pm,  is used.

          Example:
              --call=cipher-openssl

          will use the external openssl(1) executable to check the target for
          supported ciphers.

          Default settings are:
              --call=info-socket --call=cipher-socket --call=check-socket

          Just for curiosity, instead of using:
              $0 --call=info-user --call=cipher-user --call=check-user --call=score-user ...

          consider to use your own script like:
              #!/usr/bin/env perl
              usr_getinfo();usr_getciphers();usr_checkciphers();usr_score();

          :-))

      -v

          Print list of ciphers in style like: "openssl ciphers -v".
          Option used with  +ciphers  command only.

      -V

          Print list of ciphers in style like: "openssl ciphers -V".
          Option used with  +ciphers  command only.

    Options for SSL connection to target

      --cipher=CIPHER

          * 'CIPHER'    can be any string accepeted by openssl or following:
          * 'yeast'     use all ciphers from list defined herein, see  +list

          Beside the cipher names accepted by openssl, CIPHER can be the name
          of the constant or the (hex) value as defined in openssl's files.
          Currently supported are the names and constants of openssl 1.0.1k.
          Example:
            * --cipher=DHE_DSS_WITH_RC4_128_SHA
            * --cipher=0x03000066
            * --cipher=66
          will be mapped to   DHE-DSS-RC4-SHA

          Note: if more than one cipher matches, just one will be selected.

          Default is 'ALL:NULL:eNULL:aNULL:LOW' as specified in Net::SSLinfo.

      --ignore-no-connect

          A simple check if the target can be connected  will be performed by
          default.  If this check fails, the target will be ignored, means no
          more reuqested checks will be done.  As this connection check some-
          times fails due to various reasons, the check can be disabled using
          this option.

      --no-md5-cipher

          Do not use *-MD5 ciphers for other protocols than SSLv2.
          This option is only effective with  +cipher  command.

          The purpose is to avoid warnings from  IO::Socket::SSL(1)  like:
              Use of uninitialized value in subroutine entry at lib/IO/Socket/SSL.pm line 430.

          which occours with some versions of IO::Socket::SSL(1) when a *-MD5
          ciphers will be used with other protocols than SSLv2.

          Note that these ciphers will be checked for SSLv2 only.

#
#         IO::Socket::SSL->new() does not return a proper error
#         see in IO::Socket::SSL.pm  Net::SSLeay::CTX_set_cipher_list()  call
#
#     --local
#
#         It does not make much sense trying a connection with a cipher which
#         is  not supported  by the local SSL implementation. Hence these are
#         silently ignored by default.
#         With this option we try to use such ciphers also.
#
#         Option reserved for future use ...
#

      --sslv2
      --sslv3
      --tlsv1
      --tlsv11
      --tlsv12
      --tlsv13
      --dtlsv09
      --dtlsv1
      --dtlsv11
      --dtlsv12
      --dtlsv13
      --SSL, -protocol SSL

      --no-sslv2
      --no-sslv3
      --no-tlsv1
      --no-tlsv11
      --no-tlsv12
      --no-tlsv13
      --no-dtlsv09
      --no-dtlsv1
      --no-dtlsv11
      --no-dtlsv12
      --no-dtlsv13
      --no-SSL

          * 'SSL'       can be any of:
            ssl, ssl2, ssl3, sslv2, sslv3, tls1, tls1, tls11, tls1.1, tls1-1,
            tlsv1, tlsv11, tlsv1.1, tlsv1-1 (and similar variants for tlsv1.2).
          For example:  --tls1  --tlsv1  --tlsv1_1  are all the same.

          (--SSL variants):    Test ciphers for this SSL/TLS version.
          (--no-SSL variants): Don't test ciphers for this SSL/TLS version.

      --no-tcp

          Shortcut for:
          --no-sslv2 --no-sslv3 --no-tlsv1 --no-tlsv11 --no-tlsv12 --no-tlsv13

      --tcp

          Shortcut for:  --sslv2 --sslv3 --tlsv1 --tlsv11 --tlsv12 --tlsv13

      --no-udp

          Shortcut for:
          --no-dtlsv09 --no-dtlsv1 --no-dtlsv11 --no-dtlsv12 --no-dtlsv13

      --udp

          Shortcut for:  --dtlsv09 --dtlsv1 --dtlsv11 --dtlsv12 --dtlsv13

      --nullsslv2

          This option  forces  to assume that  SSLv2  is enabled  even if the
          target does not accept any ciphers.

          The target server may accept connections with  SSLv2  but not allow
          any cipher. Some checks verify if  SSLv2  is enabled at all,  which
          then would result in a failed test.
          The default behaviour is to assume that  SSLv2 is not enabled if no
          ciphers are accepted.

      --http

          Make a HTTP request if cipher is supported.

          If used twice debugging will be enabled using  environment variable
          'HTTPS_DEBUG'.

      --no-http

          Do not make HTTP request.

      --sni

          Make SSL connection in SNI mode.

      --no-sni

          Do not make SSL connection in SNI mode (default: SNI mode).

      --sni-toggle
      --toggle-sni

          Test with and witout SNI mode.

      --force-sni

          Do not check if SNI seems to be supported by  Net::SSLeay(1).
          Older versions of openssl and its libries do not support SNI or the
          SNI support is implemented buggy. By default it's checked if SNI is
          properly supported. With this option this check can be disabled.

          Be warned that this may result in improper results.

      --servername=NAME
      --sni-name=NAME

          Use NAME instead of given hostname to connect to target in SNI mode
          By  default, NAME is automatically set to the given FQDN.
          This is insufficient, when an IP instead of a FQDN was given,  then
          the connection needs to specify the correct hostname (i.g. a FQDN).

          For historical reason, the value '1' is the same as if the the real
          FQDN (given hostname) has been used.  If the value is empty, or the
          value '0' is given, no SNI name will be used.

          Note: i.g. there is no need to use this option,  as a correct value
          for the SNI name will be choosen automatically (except for IPs).
          However, it's kind of fuzzing ...

      --no-cert

          Do not get data from target's certificate, return empty string.

      --no-cert --no-cert

          Do not get data from  target's certificate,  return  default string
          of Net::SSLinfo (see  --no-cert-text=TEXT  option).

      --no-cert-text=TEXT

          Set 'TEXT' to be returned from  Net::SSLinfo if no certificate data
          is collected due to use of  --no-cert.

      --ca-depth=INT

          Check certificate chain to depth 'INT' (like openssl's -verify).

      --ca-file=FILE

          Use 'FILE' with bundle of CAs to verify target's certificate chain.

      --ca-path=DIR

          Use 'DIR' where to find CA certificates in PEM format.

      --ca-force
      --force-ca

        NOT YET IMPLEMENTED
          I. g. openssl uses default settings where to find certificate files.
          When  --ca-file=FILE  and/or  --ca-path=DIR  was used,  this default
          will be overwritten by appropriate options passed to openssl. If the
          default does not work as expected,  --force-ca  can be used to force
          setting of proper values according well known common defaults. See:
              $0 +version
              $0 +version --force-ca

          to see the used settings.


      --no-nextprotoneg

          Do not use  -nextprotoneg  option for openssl.

      --no-reconnect

          Do not use  -reconnect  option for openssl.

      --no-tlsextdebug

          Do not use  -tlsextdebug  option for openssl.

      --sclient-opt=VALUE

          Argument or option passed to openssl's  s_client  command.

    Options for cipherall command

      --range=RANGE 
      --cipherrange=RANGE

          Specify range of cipher constants to be tested by  +cipherall.
          Following RANGEs are supported (see also:  --cipherrange=RANGE):
          * 'rfc'               all ciphers defined in various RFCs
          * 'shifted'           'rfc', shifted by 64 bytes to the right
          * 'long'              like 'rfc' but more lazy list of constants
          * 'huge'              all constants  0x03000000 .. 0x0300FFFF
          * 'safe'              all constants  0x03000000 .. 0x032FFFFF
          * 'full'              all constants  0x03000000 .. 0x03FFFFFF
          * 'SSLv2'             all ciphers according RFC for SSLv2
          * 'SSLv2_long'        more lazy list of constants for SSLv2 ciphers

          Note: 'SSLv2' is the internal list used for testing SSLv2 ciphers.
          It does not make sense to use it for other protocols; however ...

      --slow-server-delay=SEC 

          Additional delay in seconds  after the server is connected  using a
          proxy or before starting STARTTLS.
          This is useful when connecting via  slow proxy chains or connecting
          to slow servers before sending the STARTTLS sequence.

      --ssl-maxciphers=CNT 

          Maximal number of ciphers sent in a sslhello (default: 32).

      --ssl-double-reneg

          Send SSL extension  'reneg_info'  even if list of ciphers includes
          TLS_EMPTY_RENEGOTIATION_INFO_SCSV (default: do not include)

# alias: --sslnodataeqnocipher --nodataeqnocipher
      --ssl-nodata-nocipher

          Some servers do not answer  (i.g. they disconnect) if  none of  the
          offered ciphers is supported by the server.

          Continue testing with next ciphers  when the target  disconnects or
          does not send data within specified timeout (see --timeout).
          Useful for TLS intolerant servers.

      --no-ssl-nodata-nocipher

          Abort testing with next ciphers when the target disconnects.

      --ssl-use-ecc

          Use supported elliptic curves.  Default on.

      --ssl-use-ec-point

          Use TLS 'ec_point_formats' extension.  Default on.

      --ssl-use-reneg

          Test for ciphers with "secure renegotiation" flag set.
          Default: don't set "secure renegotiation" flag.

      --ssl-retry=CNT

          Number of retries when connection timed-out (default: 2).

      --ssl-timeout=SEC

          Number of seconds to wait until connection is qualified as timeout.

      --dns-mx
      --mx

          Get DNS MX records for given target and check the returned targets.
          (only useful with  --starttls=SMTP).

    Options for checks and results

        Options used for  +check  command:

      --enabled

          Only print result for ciphers accepted by target.

      --disabled

          Only print result for ciphers not accepted by target.

      --ignorecase

          Checks are done case insensitive.

      --no-ignorecase

          Checks are done case sensitive. Default: case insensitive.
          Currently only checks according CN, alternate names in the target's
          certificate compared to the given hostname are effected.

    Options for output format

      --short

          Use short, less descriptive, text labels for  +check  and  +info
          command.

      --legacy=TOOL

          For compatibility with other tools,  the output format used for the
          result of the  +cipher  command can be adjusted to mimic the format
          of other SSL testing tools.

          The argument to the  --legacy=TOOL  option  is the name of the tool
          to be simulated.

          Following TOOLs are supported:
          * 'sslaudit'          format of output similar to  sslaudit
          * 'sslcipher'         format of output similar to  ssl-cipher-check
          * 'ssldiagnos'        format of output similar to  ssldiagnos
          * 'sslscan'           format of output similar to  sslscan
          * 'ssltest'           format of output similar to  ssltest
          * 'ssltestg'          format of output similar to  ssltest -g
          * 'ssltest-g'         format of output similar to  ssltest -g
          * 'sslyze'            format of output similar to  sslyze
          * 'ssl-cipher-check'  same as sslcipher
          * 'ssl-cert-check'    format of output similar to  ssl-cert-check
          * 'testsslserver'     format of output similar to  TestSSLServer.jar
          * 'thcsslcHeck'       format of output similar to  THCSSLCheck

          Note that these legacy formats only apply to  output of the checked
          ciphers. Other texts like headers and footers are adapted slightly.

          Please do not expect identical output as the TOOL  when using these
          options, it's a best guess and should be parsable in a very similar
          way.

      --legacy=compact

          Internal format: mainly avoid tabs and spaces format is as follows:
                Some Label:<-- anything right of colon is data

      --legacy=full

          Internal format: pretty print each label in its own line,  followed
          by data prepended by tab character (useful for  +info  only).

      --legacy=quick

          Internal format: use tab as separator; ciphers are printed with bit
          length (implies --tab).

      --legacy=simple

          Internal default format.

      --legacy=key

          Internal format: print name of key instead of text as label. Key is
          that of the internal data structure(s).  For ciphers and protocols,
          the corresponding hex value is used as key.  Note that these values
          are unique.

      --format=0x
      --format=\x
      --format=/x
      --format=hex
      --format=raw

          * 'raw'       Print raw data as passed from  Net::SSLinfo.
            Note:  all data will be printed as is,  without  additional label
            or formatting. It's recommended to use the  option in conjunction
            with exactly one command.  Otherwise the user needs  to know  how
            to "read"  the printed data.

          * 'hex'       Convert some data to hex: 2 bytes separated by ':'.
          * '0x'        Convert some data with hex values:
                           2 bytes preceded by '0x' and separated by a space.
          * '/x'        Same as  --format=\x
          * '\x'        Convert some data with hex values:
                           2 bytes preceded by '\x' and no separating char.

      --header

          Print formatting header.  Default for  +check,  +info,  +quick  and
          and  +cipher  only.

      --no-header

          Do not print formatting header.
          Usefull if raw output should be passed to other programs.

          Note: must be used on command line to inhibit all header lines.

      --ignore-cmd=CMD
      --ignore-output=CMD
      --no-cmd=CMD
      --no-output=CMD

          Do not print output (data or check result) for command 'CMD'. 'CMD'
          is any valid command, see  COMMANDS ,  without leading '+'.
          Option can be used multiple times.

      --score

          Print scoring results. Default for  +check.

      --no-score

          Do not print scoring results.

      --separator=CHAR
      --sep=CHAR

          'CHAR'    will be used as separator between  label and value of the
                    printed results. Default is  ':'.

      --tab

          'TAB' character (0x09, \t)  will be used as separator between label
          and value of the printed results.
          As label and value are already separated by a  TAB  character, this
          options is only useful in conjunction with the  --legacy=compact
          option.

      --showhost

          Prefix each printed line with the given hostname (target).
          The hostname will be followed by the separator character.

#         However, it applies partially if used twice for  +info.

      --win-CR

          Print windows-Style with CR LF as end of line. Default is NL only.

    Options for compatibility with other programs

        Please see other programs for detailed description (if not obvious:).
        Note that only the long form options are accepted  as most short form
        options are ambiguous.

        Following list contains only those options not shown with:

          $0 --help=alias

                Tool's Option       (Tool)          $0 Option
              #--------------------+---------------+------------------------#
              * --checks CMD        (TLS-Check.pl)  same as  +CMD
              * -h, -h=HOST         (various tools) same as  --host HOST
              * -p, -p=PORT         (various tools) same as  --port PORT
              * -t HOST             (ssldiagnos)    same as  --host HOST
              * --UDP               (ssldiagnos)    same as  --udp
              * --timeout, --grep   (ssltest.pl)    ignored
              * -r,  -s,  -t,  -x   (ssltest.pl)    ignored
              * --insecure          (cnark.pl)      ignored
              * --nopct --nocolor   (ssldiagnos)    ignored
              * -connect, -H, -u, -url, -U          ignored
              * -noSSL                              same as  --no-SSL
              * -no_SSL                             same as  --no-SSL
              #--------------------+---------------+------------------------#

        For definition of  'SSL'  see  --SSL  and  --no-SSL  above.

    Options for customization

          For general descriptions please see  CUSTOMIZATION  section below.

      --cfg_cmd=CMD=LIST
      --cfg-cmd=CMD=LIST

          Redefine list of commands. Sets  %cfg{cmd-CMD}  to  LIST.  Commands
          are written without the leading  '+'.
          CMD       can be any of:  bsi, check, http, info, quick, sni, sizes
          Example:  --cfg-cmd=sni="sni hostname"

          To get a list of commands and their settings, use:
              $0 --help=intern

          Main purpose is to reduce list of commands or print them sorted.

      --cfg-score=KEY=SCORE

          Redefine value for scoring. Sets  %checks{KEY}{score}  to  SCORE.
          Most score values are set to 10 by default. Values '0' .. '100' are
          allowed.

          To get a list of current score settings, use:
              $0 --help=score

          For deatils how scoring works, please see  SCORING  section.

          Use the  --trace-key  option for the  +info  and/or  +check command
          to get the values for  KEY.

      --cfg_checks=KEY=TEXT
      --cfg-checks=KEY=TEXT
      --cfg_data=KEY=TEXT
      --cfg-data=KEY=TEXT

          Redefine texts used for labels in output. Sets  %data{KEY}{txt}  or
          %checks{KEY}{txt}  to  TEXT.

          To get a list of preconfigured labels, use:
              $0 --help=cfg-checks
              $0 --help=cfg-data

      --cfg_text=KEY=TEXT
      --cfg-text=KEY=TEXT

          Redefine general texts used in output. Sets  %text{KEY}  to  TEXT.

          To get a list of preconfigured texts, use:
              $0 --help=cfg-text

          Note that \n, \r and \t are replaced by the corresponding character
          when read from RC-FILE.

      --cfg-hint=KEY=TEXT

          Redefine texts used for hints. Sets  %cfg{hints}{KEY}  to  TEXT.

          To get a list of preconfigured texts, use:
              $0 --help=cfg-hint

      --call=METHOD

          See  X&Options for SSL tool&.

      --usr

          Execute functions defined in  o-saft-usr.pm.

      --usr-*, --user-*

          Options ignored, but stored as is internal in  $cfg{usr-args} .
          These options can be used in  o-saft-usr.pm  or  o-saft-dbx.pm.

      --experimental

          Use experimental functionality.
          Some functionality of this tool is  under development and only used
          when this option is given.

    Options for tracing and debugging

      --n

          Do not execute, just show commands (only useful in conjunction with
          using openssl).

      Difference --trace vs. --v

          While  --v  is used to print more data,  --trace  is used to  print
          more information about internal data such as procedure names and/or
          variable names and program flow.

      --v

      --verbose

          Print more information about checks.

          Note that this option should be first otherwise some debug messages
          are missing.

          Note that  --v  is different from  -v  (see above).

      --v --v

          Print remotely checked ciphers.

      --v --v --v

          Print remotely checked ciphers one per line.

      --v --v --v --v

          Print processed ciphers (check, skip, etc.).

      --trace

          Print debugging messages.

      --trace --trace

          Print more debugging messages and pass 'trace=2' to Net::SSLeay and
          Net::SSLinfo.

      --trace --trace --trace

          Print more debugging messages and pass 'trace=3' to Net::SSLeay and
          Net::SSLinfo.

      --trace --trace --trace --trace

          Print processing of all command line arguments.

      --trace-arg, --trace--

          Print command line argument processing.

# cannot use --trace=  'cause = will be removed (CGI mode)

      --trace-cmd

          Trace execution of command processing (those given as  +*).

      --trace-key, --trace@

          Print some internal variable names in output texts (labels).
          Variable names are prefixed to printed line and enclosed in  # .
          Example without --trace-key :
              Certificate Serial Number:          deadbeef

          Example with    --trace-key :
              #serial#          Certificate Serial Number:          deadbeef

      --trace=VALUE

            Trace Option        Alias Option
          #--------------------+----------------------------#
          * --trace=1           same as  --trace
          * --trace=2           same as  --trace --trace
          * --trace=arg         same as  --trace-arg
          * --trace=cmd         same as  --trace-cmd
          * --trace=key         same as  --trace-key

      --trace-time

          Prints timestamp in trace output (implies --trace-cmd).

      --trace=FILE

          Use FILE instead of the default rc-file (.o-saft.pl, see RC-FILE).

      --trace-me

          Print debugging messages for $0 only, but not any modules.

      --trace-not-me

          Print debugging messages for modules only, but not $0 istself.

      --trace-sub
      +traceSUB

          Print formatted list of internal functions with their description.
          Not to be intended in conjunction with any target check.

      --hint

          Print hint messages (!!Hint:). 

      --no-hint

          Do not print hint messages (!!Hint:). 

      --warning

          Print warning messages (**WARNING:).

      --no-warning

          Do not print warning messages (**WARNING:).

      --exit=KEY

          For debugging only: terminate $0 at specified 'KEY'.
          For 'KEY' please see:  'grep exit= $0'

    Options vs. Commands

        For compatibility with other programs and lazy users,  some arguments
        looking like options are silently taken as commands.  This means that
        --THIS  becomes  +THIS  then. These options are:
          * --help
          * --abbr
          * --todo
          * --chain
          * --default
          * --fingerprint
          * --list
          * --version

        Take care that this behaviour may be removed in future versions as it
        conflicts with those options and commands which actually exist, like:

        --sni  vs.  +sni


LAZY SYNOPSIS

    Commands

        Following strings are treated as a command instead of target names:
          * ciphers
          * s_client
          * version

        A warning will be printed.

    Options

        We support following options, which are all identical, for lazy users
        and for compatibility with other programs.

      Option Variants

          * --port PORT
          * --port=PORT

        This applies to most such options,  --port  is just an example.  When
        used in the  RC-FILE, the  --OPTION=VALUE  variant must be used.
# does not apply to --trace option

      Option Names

        Dash '-', dot '.' and/or underscore '_' in option names are optional,
        all following are the same:
          * --no.dns
          * --no-dns
          * --no_dns
          * --nodns

        This applies to all such options,  --no-dns  is just an example.

    Targets

        Following syntax is supported also:
          $0 http://some.tld other.tld:3889/some/path?a=b

        Note that only the hostname and the port are used from an URL.

    Options vs. Commands

        See  X&Options vs. Commands&  in  OPTIONS  section above

CHECKS

        All SSL related check performed by the tool will be described here.

    General Checks

        Lookup the IP of the given hostname (FQDN), and then tries to reverse
        resolve the FQDN again.

    SSL Ciphers

        Check which ciphers are supported by target. Please see  RESULTS  for
        details of this check.

    SSL Connection

      heartbeat

        Check if heartbeat extension is supported by target.

      poodle

        Check if target is vulnerable to POODLE attack (SSLv3 enabled).

      sloth

        Check if target is vulnerable to SLOTH attack  (server offers RSA-MD5
        or ECDSA-MD5 ciphers).

      ALPN

        Check if target supports ALPN. Following messages are evaluated:
              ALPN protocol: h2-14
              No ALPN negotiated

    SSL Vulnerabilities

      ADH

        Check if ciphers for anonymous key exchange are supported: ADH|DHA.
        Such key exchanges can be sniffed.

      EDH

        Check if ephemeral ciphers are supported: DHE|EDH.
        They are necessary to support Perfect Forward Secrecy (PFS).

      BEAST

        Currently (2015) only a simple check is used: RC4 or CBC ciphers used.
        Which is any cipher with RC4, ARC4 or ARCFOUR or with CBC.
        TLSv1.2 checks are not yet implemented.

      CRIME

        Connection is vulnerable if target supports SSL-level compression.

      DROWN

        Connection is vulnerable if target supports SSLv2.

      FREAK

        Attack Against SSL/TLS to downgrade to EXPORT ciphers.
        Currently (2015) a simple check is used:   SSLv3 enabled and EXPORT
        ciphers supported by server.
        See CVE-2015-0204 and https://freakattack.com/ .

      HEARTBLEED

        Check if target is vulnerable to heartbleed attack, see CVE-2014-0160
        and http://heartbleed.com/ .

      KCI

        To perform a MiTM attack with Key Compromise Impersonation, the atta-
        cker needs to engage the victim to install and use a client certificate.
        This is considered a low risk and hence not tested here.

      Logjam

        Check if target is vulenerable to Logjam attack.
        Check if target suports  EXPORT ciphers  and/or  DH Parameter is less
        than 2048 bits. ECDH must be greater to 511 bits.

      Lucky 13

        Check if CBC ciphers are offered.
        NOTE the recommendation to be safe againts  Lucky 13  was to use  RC4
        ciphers. But they are also subjetc to attacks (see below).  Hence the
        check is only for CBC ciphers.

      RC4

        Check if RC4 ciphers are supported.
        They are assumed to be broken.
        Note that  +rc4  reports the vulnerabilitiy to the  RC4 Attack, while
        +rc4_cipher  simply reports if  RC4 ciphers are offered.  However the
        check, and hence the result, is the same.

      PFS

        Check if DHE ciphers are used.  Checks also if the TLS session ticket
        is random or not used at all.
        Currently (2015) only a simple check is used: only DHE ciphers used.
        Which is any cipher with DHE or ECDHE. SSLv2 does not support PFS.
        TLSv1.2 checks are not yet implemented.

      POODLE

        Check if target is vulnerable to  POODLE attack (just check if  SSLv3
        is enabled).

      Practical Invalid Curve Attack

        This attack allows an attacker to read the servers private key if the
        server does not check properly the passed points for a ecliptic curve
        when EDH ciphers are used.

        This check will not send multiple invalid points,  but only checks if
        the server closes the connection or responds with no matching cipher.

#      SKIP
#
#        Check if target is vulnerable to  SKIP  attack.
#       Message Skipping Attacks on TLS. Attack to force  server or client  to
#       skip messages in handshake protocol",

      SLOTH

        Currently (2016) we check for ciphers with  ECDSA, RSA-MD5.
        Checking the TLS extension 'tls-unique' is not yet implemented.

    Target (server) Configuration and Support

      BEAST, BREACH, CRIME, DROWN, FREAK, Logjam, Lucky 13, POODLE, RC4, SLOTH

        See above.

      Renegotiation

        Check if the server allows client-side initiated renegotiation.
#        This is known as "Secure Renegotiation".

      Version rollback attacks

        NOT YET IMPLEMENTED
        Check if the server allows changing the protocol.

      DH Parameter

        Check if target's DH Parameter is less 512 or 2048 bits.

    Target (server) Certificate

      Certificate Hashes

        Check that fingerprint is not MD5.
        Check that certificate private key signature is SHA2 or better.

      Root CA

        Provided certificate by target should not be a Root CA.

      Self-signed Certificate

        Certificate should not be self-signed.

      IP in CommonName or subjectAltname (RFC6125)

        NOT YET IMPLEMENTED

      Basic Constraints

        Certificate extension Basic Constraints should be CA:FALSE.
# otherwise someone can generate an intermediate cert

      OCSP, CRL, CPS

        Certificate should contain URL for OCSP and CRL.

      Private Key encyption

        Certificates signature key supports encryption.

      Private Key encyption well known

        Certificates signature key encryption algorithm is well known.

      Public Key encyption

        Certificates public key supports encryption.

      Public Key encyption well known

        Certificates public key encryption algorithm is well known.

      Public Key Modulus size

        Some (historic) SSL implementations are subject to buffer overflow if
        the key exceeds 16384 or 32768 bits. The check is against 16384 bits.

      Public Key Modulus Exponent size

        The modulus exponent should be <= 65536 as some (mainly historic) SSL
        implementations may have problems to connect.
# if > 65536 then all clients usisng MS-SSL-stack will fail to connect

      Sizes and Lengths of Certificate Settings

        Serial Number <= 20 octets (RFC5280, 4.1.2.2.  Serial Number)

        ...

      DV-SSL - Domain Validation Certificate

        The Certificate must provide:
          * Common Name '/CN=' field
          * Common Name '/CN=' in 'subject' or 'subjectAltname' field
          * Domain name in 'commonName' or 'altname' field

      EV-SSL - Extended Validation Certificate

        This check is performed according the requirements defined by the CA/
        Browser Forum  https://www.cabforum.org/contents.html .
        The certificate must provide:
          * DV - Domain Validation Certificate (see above)
          * Organization name '/O=' or 'subject' field
          * Organization name must be less to 64 characters
          * Business Category '/businessCategory=' in 'subject' field
          * Registration Number '/serialNumber=' in 'subject' field
          * Address of Place of Business in 'subject' field

        Required are: '/C=', '/ST=', '/L='

        Optional are: '/street=', '/postalCode='

          * Validation period does not exceed 27 month

        See  LIMITATIONS  also.

    Target (server) HTTP(S) Support

      STS header

        Using STS is no perfect security.  While the very first request using
        http: is always prone to a MiTM attack, MiTM is possible to following
        requests again, if STS is not well implemented on the server.
          * Request with http: should be redirected to https:
          * Redirects should use status code 301 (even others will work)
          * Redirect's Location header must contain schema https:
          * Redirect's Location header must redirect to same FQDN
          * Redirect may use Refresh instead of Location header (not RFC6797)
          * Redirects from HTTP must not contain STS header
          * Answer from redirected page (HTTPS) must contain STS header
          * Answer from redirected page for IP must not contain STS header
          * STS header must contain includeSubDirectoy directive
          * STS header max-age should be less than 1 month

      Public Key Pins header
        TBD - to be described ...

    Compliances

        Note that it is not possible to satisfy all following compliances.
        Best match is: 'PSF' and 'ISM' and 'PCI' and 'lazy BSI TR-02102-2'.
# example: fancyssl.hboeck.de
        In general it is difficult to satisfy all conditions of a compliance,
        and it is also difficult to check  all these conditions.  That is why
        some compliance checks are not completely implemented.
        For details see below please.

        Also note that in the  RC-FILE  the output of results for some checks
        is disabled by default. A  '!!Hint:'  message will be printed, if any
        of these checks are used.

          * FIPS-140
          * ISM
          * PCI
          * BSI TR-02102-2
          * BSI TR-03116-4
          * RFC 6125
          * RFC 7525

#   NSA Suite B
      BSI TR-02102-2 (+bsi-tr-02102+ +bsi-tr-02102-)
        Checks if connection and ciphers are compliant according TR-02102-2,
        see https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen
        /TechnischeRichtlinien/TR02102/BSI-TR-02102-2_pdf.pdf?__blob=publicationFile

        (following headlines are taken from there)

        3.2.1 Empfohlene Cipher Suites

        3.2.2 Übergangsregelungen

          RC4 allowed temporary for TLS 1.0. Only if  TLS 1.1  and  TLS 1.2
          cannot be supported.

        3.2.3 Mindestanforderungen für Interoperabilität

          Must at least support: ECDHE-ECDSA-* and ECDHE-RSA-*

        3.3 Session Renegotation

          Only server-side (secure) renegotiation allowed (see RFC 5280).

        3.4 Zertifikate und Zertifikatsverifikation

          Must have 'CRLDistributionPoint' or 'AuthorityInfoAccess'.

          MUST have 'OCSP URL'.

          'PrivateKeyUsage' must not exceed three years for certificate and
          must not exceed five years for CA certificates.

          'Subject',  'CommonName'  and  'SubjectAltName'  must not contain
          a wildcard.

          Certificate itself must be valid according dates if validity.
          Note that  the validity check relies on the years provided by the
          'before' and 'after'  values of the certificate only. For example
          a certificate having  "from Jan 2013 to Mar 2016"  is  considered
          valid even the validity is more than three years.

          All certificates in the chain must be valid.
          **NOT YET IMPLEMENTED**

          Above conditions are not required for lazy checks.

        3.5 Domainparameter und Schlüssellängen

          **NOT YET IMPLEMENTED**

#        --------------+---------------+--------
#                Minimale
# Algorithmus    Schlüssellänge  Verwendung bis
#        --------------+---------------+--------
# Signaturschlüssel für Zertifikate und Schlüsseleinigung
#   ECDSA        224 Bit         2015
#   ECDSA        250 Bit         2019+
#     DSS        2000 Bit3       2019+
#     RSA        2000 Bit3       2019+
# Statische Diffie-Hellman Schlüssel
#          CDH        224 Bit         2015
#          CDH        250 Bit         2019+
#      DH        2000 Bit        2019+
# Ephemerale Diffie-Hellman Schlüssel
#          CDH        224 Bit         2015
#          CDH        250 Bit         2019+
#      DH        2000 Bit        2019+
#        --------------+---------------+--------

        3.6 Schlüsselspeicherung

          This requirement is not testable from remote.

        3.7 Umgang mit Ephemeralschlüsseln

          This requirement is not testable from remote.

        3.8 Zufallszahlen

          This requirement is not testable from remote.

      BSI TR-03116-4 (+bsi-tr-03116+ +bsi-tr-03116-)
        Checks if connection and ciphers are compliant according TR-03116-4,
        see https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen 
        /TechnischeRichtlinien/TR03116/BSI-TR-03116-4.pdf?__blob=publicationFile

        (following headlines are taken from there)

        2.1.1 TLS-Versionen und Sessions

          Allows only TLS 1.2.

        2.1.2 Cipher Suites

          Cipher suites must be ECDHE-ECDSA or -RSA with AES128 and SHA265. 
          For curiosity, stronger cipher suites with AES256 and/or SHA384 are
          not not allowed. To follow this curiosity the +bsi-tr-03116- (lazy)
          check allows the stronger cipher suites ;-)

        2.1.1 TLS-Versionen und Sessions

          The TLS session lifetime must not exceed 2 days.

        2.1.4.2 Encrypt-then-MAC-Extension

        2.1.4.3 OCSP-Stapling

          MUST have 'OCSP Stapling URL'.

        4.1.1 Zertifizierungsstellen/Vertrauensanker

          Certificate must provide all root CAs. (NOT YET IMPLEMENTED).

          Should use a small certificate trust chain.

        4.1.2 Zertifikate

          Must have 'CRLDistributionPoint' or 'AuthorityInfoAccess'.

          End-user certificate must not be valid longer than 3 years.
          Root-CA certificate must not be valid longer than 5 years.

          Certificate extension 'pathLenConstraint' must exist, and should be
          a small value ("small" is not defined).

          All certificates must contain the extension 'KeyUsage'.

          Wildcards for 'CN' or 'Subject' or 'SubjectAltName' are not allowed
          in any certificate.

          EV certificates are recommended (NOT YET checked properly).

        4.1.3 Zertifikatsverifikation

          Must verify all certificates in the chain down to their root-CA.
          (NOT YET IMPLEMENTED).

          Certificate must be valid according issue and expire date.

          All Checks must be doen for all certificates in the chain.

        4.1.4 Domainparameter und Schlüssellängen

          This requirement is not testable from remote.

        4 5.2 Zufallszahlen

          This requirement is not testable from remote.

      RFC 6125 (+rfc6125)
        Checks values 'CommonName', 'Subject' and 'SubjectAltname'  of the
        certificate for:
           * must all be valid characters for DNS
           * must not contain more than one wildcards
           * must not contain invalid wildcards
           * must not contain invalid IDN characters

      RFC 7525 (+rfc7525)
        Checks if connection and ciphers are compliant according RFC 7525.
        See http://tools.ietf.org/rfc/rfc7525.txt
        (following headlines are taken from there)

        3.1.1.  SSL/TLS Protocol Versions

          SSLv2 and SSLv3 must not be supportetd.
          TLSv1 should only be supported if there is no TLSv1.1 or TLSv1.2.
          Either TLSv1.1 or TLSv1.2 must be supported, prefered is TLSv1.2.

        3.1.2.  DTLS Protocol Versions

          DTLSv1 and DTLSv1.1 must not be supported.

        3.1.3.  Fallback to Lower Versions

          (check implecitely done by 3.1.1, see above)

        3.2.  Strict TLS

          Check if server provides Strict Transport Security.
          (STARTTLS check NOT YET IMPLEMENTED).

        3.3.  Compression

          Compression on TLS must not be supported.

        3.4.  TLS Session Resumption

          Server must support resumtion and random session tickets.
          (Randomnes of session tickets implemented YET experimental.)

          Check if ticket is authenticated and encrypted NOT YET IMPLEMENTED.

        3.5.  TLS Renegotiation

          Server must support renegotiation.

        3.6.  Server Name Indication

          (Check for SNI support implemented experimental.)

        4.  Recommendations: Cipher Suites

        4.1.  General Guidelines
        4.2.  Recommended Cipher Suites

          Check for recommended ciphers.

        4.3.  Public Key Length

          DH parameter must be at least 256 bits or 2048 its with EC.
          (Check currently, 4/2016, based on openssl which may not provide DH
           parameters for all ciphers.)

        4.5.  Truncated HMAC

          TLS extension "truncated hmac" must not be used.

        6.  Security Considerations
        6.1.  Host Name Validation

          Given hostname must matches hostname in certificate's subject.

        6.2.  AES-GCM
        6.3.  Forward Secrecy
        6.4.  Diffie-Hellman Exponent Reuse
          (NOT YET IMPLEMENTED).

        6.5.  Certificate Revocation

          OCSP and CRL Distrbution Point in cetificate must be defined.


# score will be removed, so don't anounce it
#SCORING
#
#        Coming soon ...


OUTPUT

        All output is designed to make it  easily parsable by postprocessors.
        Following rules are used:
          * Lines for formatting or header lines start with  '='.
          * Lines for verbosity or tracing start with  '#'.
          * Errors and warnings start with  '**'.
          * Empty lines are comments ;-)
          * Label texts end with a separation character; default is  ':'.
          * Label and value for all checks are separated by at least one  TAB
            character.
          * Texts for additional information are enclosed in '<<'  and  '>>'.
          * 'N/A'  is used when no proper informations was found or provided.
            Replace  'N/A'  by whatever you think is adequate:  "No answer",
            "Not available",  "Not applicable",  ...

        When used in  --legacy=full  or --legacy=simple  mode, the output may
        contain formatting lines for better (human) readability.

    Postprocessing Output

        It is recommended to use the   --legacy=quick   option, if the output
        should be postprocessed, as it omits the default separation character
        (':' , see above) and just uses on single tab character (0x09, \t  or
        TAB) to separate the label text from the text of the result. Example:
              Label of the performed checkTABresult

        More examples for postprocessing the output can be found here:
              https://github.com/OWASP/O-Saft/blob/master/contrib


CUSTOMIZATION

        This tools can be customized as follows:

        * Using command line options

            This is a simple way to redefine  specific settings.  Please  see
            CONFIGURATION OPTIONS  below.

        * Using Configuration file

            A configuration file can contain multiple configuration settings.
            Syntax is simply  KEY=VALUE. Please see CONFIGURATION FILE below.

        * Using resource files

            A resource file can contain multiple command line options. Syntax
            is the same as for command line options iteself.  Each  directory
            may contain its own resource file. Please see  RC-FILE  below.

        * Using debugging files

            These files are - nomen est omen - used for debugging purposes.
            However, they can be (mis-)used to redefine all settings too.
            Please see  DEBUG-FILE  below.

        * Using user specified code

            This file contains  user specified  program code.  It can also be
            (mis-)used to redefine all settings. Please see USER-FILE  below.

        Customization is done by redefining values in internal data structure
        which are:  %cfg,  %data,  %checks,  %text,  %scores.

        Unless used in  DEBUG-FILE  or  USER-FILE,  there is  no need to know
        these internal data structures or the names of variables; the options
        will set the  proper values.  The key names being part of the option,
        are printed in output with the  --trace-key  option.

        I.g. texts (values) of keys in  %data are those used in output of the
        "Information" section. Texts of keys in  %checks  are used for output
        in "Performed Checks" section.  And texts of keys in  %text  are used
        for additional information lines or texts (mainly beginning with '=').

      Configuration File vs. RC-FILE vs. DEBUG-FILE

        * CONFIGURATION FILE

            Configuration files must be specified with one of the  --cfg-*
            options. The specified file can be a valid path. Please note that
            only the characters:  a-zA-Z_0-9,.\/()-  are allowed as pathname.
            Syntax in configuration file is:  'KEY=VALUE'  where 'KEY' is any
            key as used in internal data structure.

        * RC-FILE

            Resource files are searched for and used automatically.
            For details see  RC-FILE  below.

        * DEBUG-FILE

            Debug files are searched for and used automatically.
            For details see  DEBUG-FILE  below.

        * USER-FILE

            The user program file is included only  if the  --usr  option was
            used. For details see  USER-FILE  below.


    CONFIGURATION OPTIONS

        Configuration options are used to redefine  texts and labels or score
        settings used in output. The options are:
          * --cfg-cmd=KEY=LIST
          * --cfg-checks=KEY=TEXT
          * --cfg-data=KEY=TEXT
          * --cfg-hint=KEY=TEXT
          * --cfg-text=KEY=TEXT

        KEY  is the key used in the internal data structure, and  TEXT is the
        value to be set for this key.  Note that unknown keys will be ignored
        silently.

        If KEY=TEXT is an exiting filename, all lines from that file are read
        and set. For details see  CONFIGURATION FILE  below.

        NOTE that such configuration options should be used before any --help 
        or  --help=*  option, otherwise the changed setting is not visible.

    CONFIGURATION FILE

        Note that the file can contain KEY=TEXT pairs for any kind of the
        configuration as given by the  --cfg-CFG  option.

        For example  when used with  --cfg-text=file  only values for  %text
        will be set, when used with  --cfg-data=file  only values for  %data
        will be set, and so on. KEY is not used  when KEY=TEXT is an existing
        filename. Though, it's recommended to use a non-existing key, i.e.:
        --cfg-text=my_file=some/path/to/private/file .

    RC-FILE

        The rc-file will be searched for in the working directory only.

        The name of the rc-file is the name of the program file prefixed by a
        '.'  (dot),  for example:  '.o-saft.pl'.

        A  rc-file  can contain any of the commands and options valid for the
        tool itself. The syntax for them is the same as on command line. Each
        command or option must be in a single line. Any empty or comment line
        will be ignored. Comment lines start with  '#'  or  '='.

        Note that options with arguments must be used as  'KEY=VALUE' instead
        of  'KEY VALUE'.

        Configurations options must be written like '--cfg-CFG=KEY=VALUE'.
        Where 'CFG' is any of:  cmd, check, data, text  or score and 'KEY' is
        any key from internal data structure (see above).

        All commands and options given on command line will  overwrite  those
        found in the rc-file.

    DEBUG-FILE

        All debugging functionality is defined in  o-saft-dbx.pm , which will
        be searched for using paths available in  '@INC'  variable.

        Syntax in this file is perl code.  For details see  DEBUG  below.

    USER-FILE

        All user functionality is defined in   o-saft-usr.pm ,  which will be
        searched for using paths available in  '@INC'  variable.

        Syntax in this file is perl code.

        All functions defined in   o-saft-usr.pm   are called when the option
        --usr  was given.  The functions are defined as empty stub,  any code
        can be inserted as need.  Please see   perldoc o-saft-usr.pm   to see
        when and how these functions are called.

    SHELL TWEAKS

        Configurering the shell environment where the tool is startet, is not
        not really a task for the tool itself, but it can simplify your life,
        somehow.

        There exist customizations for some commonly used shells,  please see
        the files in the ./contrib/ directory.


CIPHER NAMES

        While the SSL/TLS protocol uses integer numbers to identify  ciphers,
        almost all tools use some kind of  "human readable"  texts for cipher
        names. 

        These numbers (which are most likely written  as hex values in source
        code and documentations) are the only true identifier, and we have to
        rely on the tools that they use the proper integers.

        As such integer or hex numbers are difficult to handle by humans,  we
        decided to use human readable texts. Unfortunately no common standard
        exists how to construct the names and map them to the correct number.
        Some, but by far not all, oddities are described in  X&Name Rodeo&.

        The rules for specifying cipher names are:
          1) textual names as defined by IANA (see [IANA])
          2) mapping of names and numbers as defined by IANA (see [IANA])
          3) '-'  and  '_'  are treated the same
          4) abbreviations are allowed, as long as they are unique
          5) beside IANA, openssl's cipher names are preferred
          6) name variants are supported, as long as they are unique
          7) hex numbers can be used

        [IANA]    http://www.iana.org/assignments/tls-parameters/tls-parameters.txt September 2013

        [openssl] ... openssl 1.0.1

        If in any doubt, use  +list --v  to get an idea about the mapping.
        Use  --help=regex  to see which regex are used to handle all variants
        herein.

        Mind the traps and dragons with cipher names and what number they are
        actually mapped to. In particular when  --lib,  --exe  or  --openssl 
        options are in use. Always use these options with  +list command too.

    Name Rodeo

        As said above, the  SSL/TLS protocol uses integer numbers to identify
        ciphers, but almost all tools use some kind of  human readable  texts
        for cipher names. 

        For example the cipher commonly known as 'DES-CBC3-SHA' is identified
        by '0x020701c0' (in openssl) and has 'SSL2_DES_192_EDE3_CBC_WITH_SHA'
        as constant name. A definition is missing in IANA, but there is 
        'TLS_RSA_WITH_3DES_EDE_CBC_SHA'.
        It's the responsibility of each tool to map the human readable cipher
        name to the correct (hex, integer) identifier.

        For example Firefox uses  'dhe_dss_des_ede3_sha',  which is what?

        Furthermore, there are different acronyms for the same thing in use.
        For example  'DHE'  and  'EDH'  both mean "Ephemeral Diffie-Hellman".
        Comments in the  openssl(1)  sources mention this.  And for curiosity
        these sources use both in cypher names, but allow  'EDH'  as shortcut
        only in openssl's "ciphers"  command. Wonder about (up to 1.0.1h):
              openssl ciphers -V EDH
              openssl ciphers -V DHE
              openssl ciphers -V EECDH
              openssl ciphers -V ECDHE

        Next example is  'ADH'  which is also known as  'DH_anon' or 'DHAnon'
        or  'DHA'  or  'ANON_DH'. 

        You think this is enough? Then have a look how many acronyms are used
        for  "Tripple DES".

        Compared to above, the interchangeable use of  '-'  vs.  '_' in human
        readable cipher names is just a very simple one. However, see openssl
        again what following means (returns):
              openssl ciphers -v RC4-MD5
              openssl ciphers -v RC4+MD5
              openssl ciphers -v RC4:-MD5
              openssl ciphers -v RC4:!MD5
              openssl ciphers -v RC4!MD5

        Looking at all these oddities, it would be nice to have a common unique
        naming scheme for cipher names. We have not.  As the SSL/TLS protocol
        just uses a number, it would be natural to use the number as uniq key
        for all cipher names, at least as key in our internal sources.

        Unfortunately, the assignment of ciphers to numbers  changed over the
        years, which means that the same number refers to a  different cipher
        depending on the standard, and/or tool, or version of a tool you use.

        As a result, we cannot use human readable cipher names as  identifier
        (aka unique key), as there are  to many aliases  for the same cipher.
        And also the number  cannot be used  as unique key, as a key may have
        multiple ciphers assigned.


KNOWN PROBLEMS

        This section describes knwon problems, and known error messages which
        may occour when using $0. This sections can be used as FAQ too
        as it gives hints and workarounds.

    Segmentation fault

        Sometimes  the program terminates with a  'Segmentation fault'.  This
        mainly happens if the target does not return certificate information.
        If so, the  --no-cert  option may help.

    **WARNING: empty result from openssl; ignored at ...

        This most likely occurs when the  provided cipher is  not accepted by
        the server, or the server expects client certificates.

    **WARNING: unknown result from openssl; ignored at ...

        This most likely occurs when the openssl(1) executable is used with a
        very slow connection. Typically the reason is a connection timeout.
        Try to use  --timeout=SEC  option.
        To get more information, use  --v --v  and/or  --trace  also.

    **WARNING: undefined cipher description

        May occour if ciphers are checked, but no description is available for
        them herein. This results in printed cipher checks like:
              EXP-KRB5-RC4-MD5                no       <<undef>>

        instead of:
              EXP-KRB5-RC4-MD5                no       weak

    **WARNING: Can't make a connection to your.tld:443; no initial data
    **WARNING: Can't make a connection to your.tld:443; target ignored

        This message occours if the underlaying  SSL library (i.e. libssl.a)
        was not able to connect to the target. Known observed reasons are:
          * target does not support SSL protocol on specified port
          * target expects a client certificate in ClientHello message

        More details why the connection failed can be seen using  --trace=2 .

        If the targets supports SSL, it should be at least possible to check
        for supported ciphers using  +cipherall  instead of  +cipher .


    Use of uninitialized value $headers in split ... do_httpx2.al)

        The warning message (like follows or similar):

              Use of uninitialized value $headers in split at blib/lib/Net/SSLeay.pm
              (autosplit into blib/lib/auto/Net/SSLeay/do_httpx2.al) line 1290.

        occurs if the target refused a connection on port 80.
        This is considered a bug in  Net::SSLeay(1).
        Workaround to get rid of this message: use  --no-http  option.

    invalid SSL_version specified at ... IO/Socket/SSL.pm

        This error may occur on systems where a specific  SSL version is not
        supported. Subject are mainly  SSLv2, SSLv3 TLSv1.3 and DTLSv1.
        For DTLSv1 the full message looks like:
              invalid SSL_version specified at C:/programs/perl/perl/vendor/lib/IO/Socket/SSL.
        See also  X&Note on SSL versions& .

        Workaround: use option: --no-sslv2 --no-sslv3 --no-tlsv13 --no-dtlsv1

    Use of uninitialized value $_[0] in length at (eval 4) line 1.

        This warning occours with IO::Socket::SSL 1.967, reason is unknown.
        It seems not to harm functionality, hence no workaround, just ignore.

    Use of uninitialized value in subroutine entry at lib/IO/Socket/SSL.pm line 430.

        Some versions of  IO::Socket::SSL return this error message if  *-MD5
        ciphers are used with other protocols than SSLv2.

        Workaround: use  --no-md5-cipher  option.

    Can't locate auto/Net/SSLeay/CTX_v2_new.al in @INC ...

        Underlaying library doesn't support the required SSL version.
        See also  X&Note on SSL versions& .

        Workaround: use  --ssl-lazy option, or corresponding --no-SSL option.

    Read error: Connection reset by peer (,199725) at blib/lib/Net/SSLeay.pm\
    (autosplit into blib/lib/auto/Net/SSLeay/tcp_read_all.al) line 535.

        Error reported by some Net::SSLeay versions. Reason may be a timeout.
        This error cannot be omitted or handled properly.

        Workaround: try to use same call again (no guarantee, unfortunatelly)
# see Net::SSLinfo.pm for details

    openssl: ...some/path.../libssl.so.1.0.0: no version information available (required by openssl)

        Mismatch of  openssl executable  and loaded underlaying library. This
        most likely happens when options  --lib=PATH  and/or  --exe=PATH  are
        used.  See also  X&Note on SSL versions& .

        Hint: use following commands to get information about used libraries:
              $0 +version
              $0 --v --v +version

    Integer overflow in hexadecimal number at ...

        This error message may occour on  32-bit systems if perl was not com-
        piled with proper options. I.g. perl automatically converts the value
        to a floating pont number.
        Please report a bug with output of following command:
          $0 +s_client +dump your.tld

    <<openssl did not return DH Paramter>>

        Text may be part of a value. This means that all checks according  DH
        parameters and logkam attack cannot be done.

        Workaround: try to use  --openssl=TOOL  option.

        This text may appears in any of the compliance checks (like +rfc7525)
        which may be a false positive.  For these checks openssl is also used
        to get the DH Parameter.

        Workaround: not available yet

    No output with  +help  and/or  --help=todo

        On some (mainly Windows-based) systems using
              $0 +help
              $0 --help

        does not print anything.

        Workaround: use  --v  option.
              $0 +help --v

        or
              $0 +help | more

    **WARNING: on MSWin32 additional option  --v  required, sometimes ...

        On some (mainly Windows-based) systems  this may happen  when calling
        for example:
              $0 --help=FAQ

        which then may produce:
              **WARNING: on MSWin32 additional option  --v  required, sometimes ...
              === reading: ./.o-saft.pl (RC-FILE done) ===
              === reading: Net/SSLinfo.pm (O-Saft module done) ===
              **USAGE: no command given
              # most common usage:
                o-saft.pl +info   your.tld
                o-saft.pl +check  your.tld
                o-saft.pl +cipher your.tld
              # for more help use:
                o-saft.pl --help

        Workaround: use full path to perl.exe, for example
          C:\Programs\perl\bin\perl.exe $0 --help=FAQ


    Performance Problems

        There are various reasons when the program responds slow, or seems to
        hang. Beside the problems described below performance issues are most
        likely a target-side problem. Most common reasons are:

          a) DNS resolver problems
             Try with  --no-dns

          b) target does not accept connections for https
             Try with  --no-http

          c) target's certificate is not valid
             Try with  --no-cert

          d) target expects that the client provides a client certificate
             No option provided yet ...

          e) target does not handle Server Name Indication (SNI)
             Try with  --no-sni

          f) use of external openssl(1) executable
             Use  --no-openssl

        Other options which may help to get closer to the problem's cause:
        --timeout=SEC,  --trace,  --trace=cmd


LIMITATIONS

    Commands

        Some commands cannot be used together with others, for example:
        +cipher,  +ciphers,  +list,  +libversion,  +version,  +check,  +help,
        +protocols .
 
        +quick  should not be used together with other commands, it returns
        strange output then.

        +protocols  requires  openssl(1)  with support for  '-nextprotoneg'
        option. Otherwise the value will be empty.

    Options

        The option  --port=PORT  must preceed  --host=HOST  for a target like
        HOST:PORT  .

        The characters  '+' and '='  cannot be used for  --separator  option.

        Following strings should not be used in any value for options:
          '+check', '+info', '+quick', '--header'
        as they my trigger the  --header   option unintentional.

        The used  timeout(1)  command cannot be defined with a full path like
        openssl(1)  can with the  --openssl=path/to/openssl .

        --cfg-text=file  cannot be used to redefine the texts  'yes' and 'no'
        as used in the output for  +cipher  command.

    Checks (general)

      +constraints

          This check is only done for the certificate provided by the target.
          All other certificate in the chain are not checked.

          This is currently (2015) a limitation in $0.

    Broken pipe

        This error message most likely means that the connection to specified
        target was not possible (firewall or whatever reason).

    Target Certificate Chain Verification

        The systems default capabilities i.e. libssl.so, openssl, are used to
        verify the target's certificate chain.  Unfortunately various systems
        have implemented different  approaches and rules how identify and how
        to report a successful verification.  As a consequence  this tool can
        only return the  same information about the chain verification as the
        used underlying tools.  If that information is trustworthy depends on
        how trustworthy the tools are.

        These limitations apply to following commands:
          * +verify
          * +selfsigned

        Following commands and options are useful to get more information:
          * +chain_verify,  +verify,  +error_verify,  +chain,  +s_client
          * --ca-file,  --ca-path,  --ca-depth

    User Provided Files

        Please note that there cannot be any guarantee that the code provided
        in the  DEBUG-FILE  o-saft-dbx.pm  or  USER-FILE  o-saft-usr.pm  will
        work flawless. Obviously this is the user's responsibility.

    Problems and Errors

        Checking the target for supported ciphers may return that a cipher is
        not supported by the server  misleadingly.  Reason is most likely  an
        improper timeout for the connection. See  --timeout=SEC  option.

        If the specified targets accepts connections but does not speak  SSL,
        the connection will be closed after the system's TCP/IP-timeout. This
        script will hang (about 2-3 minutes).

        If reverse DNS lookup fails, an error message is returned as hostname,
        like:  '<<gethostbyaddr() failed>>'.
        Workaround to get rid of this message: use  --no-dns  option.

        All checks for EV are solely based on the information provided by the
        certificate.

        Some versions of openssl (< 1.x) may not support all required options
        which results in various error messages,  or  more worse,  may not be
        visibale at all.
        Following table shows the openssl option and how to disbale it within
        o-saft:
          * nextprotoneg        --no-nextprotoneg
          * reconnect           --no-reconnect
          * tlsextdebug         --no-tlsextdebug

    Poor Systems

        Use of  openssl(1)  is disabled by default on  Windows due to various
        performance problems. It needs to be enabled with  --openssl  option.

        On Windows the usage of  "openssl s_client" needs to be enabled using
        --s_client  option.

        On Windows it's a pain to specify the path for  --openssl=..  option.
        Variants are:
          * --openssl=/path/to/openssl.exe
          * --openssl=X:/path/to/openssl.exe
          * --openssl=\path\to\openssl.exe
          * --openssl=X:\path\to\openssl.exe
          * --openssl=\\path\\to\\openssl.exe
          * --openssl=X:\\path\\to\\openssl.exe

        You have to fiddle around to find the proper one.

    Debug and Trace Output

        When both  --trace=key  and  --trace=cmd  options are used, output is
        mixed, obviously. Hint: output for --trace=cmd always contains "CMD".


DEPENDENCIES

        All perl modules and all  private moduels and files  will be searched
        for using paths  available in the  '@INC'  variable.  '@INC'  will be
        prepended by following paths:

          * .
          * ./lib
          * INSTALL_PATH
          * INSTALL_PATH/lib

        Where  'INSTALL_PATH'  is the path where the tool is installed.
        To see which files have been included use:
              $0 +version --v --user

    Perl Modules

        * IO::Socket::SSL(1)
        * IO::Socket::INET(1)
        * Net::SSLeay(1)
        * Net::SSLinfo
        * Net::SSLhello

    Additional files used if requested

        * .o-saft.pl
        * o-saft-dbx.pm
        * o-saft-man.pm
        * o-saft-usr.pm
        * o-saft-README


INSTALLATION

        The tool can be installed in any path. It just requres the modules as
        described in  DEPENDENCIES  above. However, it's recommended that the
        modules  Net::SSLhello  and  Net::SSLinfo  are found in the directory
        './Net/'  where  o-saft.pl  is installed.

        For security reasons, most modern libraries  disabled or even removed
        insecure or "dirty" functionality.  As the purpose of this tool is to
        detect such insecure settings, functions, etc.,  it needs these dirty
        things enabled. It needs (incomplete list):

          * insecure protocols like SSLv2, SSLv3
          * more ciphers enabled, like NULL-MD5, AECDH-NULL-SHA, etc.
          * some SSL extensions and options

        Therefore we recommend to compile and install at least following:

          * OpenSSL  with SSLv2, SSLv3 and more ciphers enabled
          * Net::SSLeay  compiled with openssl version as described before.

        Please read the  SECURITY  section first before following the install
        instructions below.

    OpenSSL

        Currently it is recommend to use either the openssl version from
         https://github.com/PeterMosmans/openssl/ which requires compilation,
        see  X&Example: Compile OpenSSL&, or use any of the precomiled versions
        which are available for several platforms at https://testssl.sh/ .

        The sources are available at
          * https://github.com/PeterMosmans/openssl/archive/1.0.2-chacha.zip
        The precomiled static versions are available at
          * https://github.com/drwetter/testssl.sh/tree/master/bin

        For all following installation examples we assume:
          * openssl-1.0.2-chacha.zip or openssl-1.0.2d.tar.gz
          * /usr/local as base installation directory
          * a bourne shell (sh) compatible shell

    Example: Precompiled OpenSSL

        Simply download the tarball or zip file for your platform, unpack it,
        and install (copy) the binaries into a directory of your choice.

    Example: Compile OpenSSL

        OpenSSL can be used from http://openssl.org/ or, as recommended, from
        https://github.com/PeterMosmans/openssl/ .

        OpenSSL-chacha
        Compiling and installing the later is as simple as:

              unzip openssl-1.0.2-chacha.zip
              cd openssl-1.0.2-chacha
              ./config --shared -Wl,-rpath=/usr/local/lib
              make
              make test
              make install

        which will install openssl, libssl.so, libcrypto.so  and some include
        files as well as the include files in  /usr/local/ .
        The shared version of the libraries are necessary for  Net::SSLeay.

        OpenSSL.org
        Building openssl from the offical  openssl.org  sources requires some
        patching before compiling and installing the libraries and binaries.

        Example with openssl-1.0.2d:

              echo == unpack tarball
              tar xf openssl-1.0.2d.tar.gz
              cd openssl-1.0.2d

              echo == backup files to be modified
              cp ssl/s2_lib.c{,.bak}
              cp ssl/s3_lib.c{,.bak}
              cp ssl/ssl3.h{,.bak}
              cp ssl/tls1.h{,.bak}

              echo == patch files
              vi ssl/tls1.h         +/TLS1_ALLOW_EXPERIMENTAL_CIPHERSUITES/
                       # define TLS1_ALLOW_EXPERIMENTAL_CIPHERSUITES  1
              vi ssl/ssl3.h ssl/s{2,3}_lib.c   +"/# *if 0/"
                       #==> remove all   # if 0  and corresponding  #endif 
                       #    except if lines contain:
                       #        _FZA
                       #        /* Fortezza ciphersuite from SSL 3.0
                       #        /* Do not set the compare functions,
                       #        if (s->shutdown & SSL_SEND_SHUTDOWN)

              echo == configure with static libraries
              echo omitt the zlib options if zlib-1g-dev is not installed
              echo omitt the krb5 options if no kerberos libraries available
              ./config --prefix=/usr/local --openssldir=/usr/local/ssl \
                  enable-zlib zlib zlib-dynamic enable-ssl2 \
                  enable-krb5 --with-krb5-flavor=MIT \
                  enable-mdc2 enable-md2 enable-rc5  enable-rc2 \
                  enable-cms  enable-ec  enable-ec2m enable-ecdh enable-ecdsa \
                  enable-gost enable-seed enable-idea enable-camellia \
                  enable-rfc3779 enable-ec_nistp_64_gcc_128 \
                  experimental-jpake -fPIC \
                  -DTEMP_GOST_TLS -DTLS1_ALLOW_EXPERIMENTAL_CIPHERSUITES \
                  shared

              echo == make binaries and libraries
              make depend
              make
              make test
              make install

              echo == if you want static binaries and libraries
              make clean
              echo same ./config as before but without shared option
              ./config --prefix=/usr/local --openssldir=/usr/local/ssl \
                  enable-zlib zlib zlib-dynamic enable-ssl2 \
                  enable-krb5 --with-krb5-flavor=MIT \
                  enable-mdc2 enable-md2 enable-rc5  enable-rc2 \
                  enable-cms  enable-ec  enable-ec2m enable-ecdh enable-ecdsa \
                  enable-gost enable-seed enable-idea enable-camellia \
                  enable-rfc3779 enable-ec_nistp_64_gcc_128 \
                  experimental-jpake -fPIC  -static \
                  -DTEMP_GOST_TLS -DTLS1_ALLOW_EXPERIMENTAL_CIPHERSUITES
              make depend
              make
              make test
              echo next make will overwrite the previously installed dynamic
              echo shared openssl binary with the static openssl binary
              make install

    Example: Compile Net::SSLeay

        To enable support for ancient protocol versions,  Net::SSLeay must be
        compiled manually after patching 'SSLeay.xs' (see below).
        Reason is, that  Net::SSLeay  enables some functionality for  SSL/TLS
        according the identified openssl version. There is, currently (2015),
        no possibility to enable this functionality  by passing options on to
        the configuration script 'perl Makefile.PL'.

        Building our own library and module (with openssl from '/usr/local'):

              echo == unpack tarball
              tar xf Net-SSLeay-1.72.tar.gz
              cd Net-SSLeay-1.72

              echo == patch files
              echo "edit SSLeay.xs and change some #if as described below"
              env OPENSSL_PREFIX=/usr/local perl Makefile.PL PREFIX=/usr/local \
                    INC=/usr/local/include  DEFINE=-DOPENSSL_BUILD_UNSAFE=1
              make
              make install
              cd /tmp && $0 +version

        SSLeay.xs needs to be changed as follows:
          * search for
              #ifndef OPENSSL_NO_SSL2
              #if OPENSSL_VERSION_NUMBER < 0x10000000L

              const SSL_METHOD *
              SSLv2_method()

              #endif
              #endif

              #ifndef OPENSSL_NO_SSL3
              #if OPENSSL_VERSION_NUMBER < 0x10002000L

              const SSL_METHOD *
              SSLv3_method()

              #endif
              #endif

          * and replace by
              const SSL_METHOD *
              SSLv2_method()

              const SSL_METHOD *
              SSLv3_method()

        Note that  Net::SSLeay  will be installed in '/usr/local/' then. This
        can be adapted to your needs by passing another path to the  'PREFIX'
        and  'DESTDIR'  parameter.

        Following command can be used to check  which methods are avilable in
        Net::SSLeay, hence above patches can be verified:

              perl -MNet::SSLinfo -le 'print Net::SSLinfo::test_ssleay();'

    Testing OpenSSL

        After installation as descibed above finished, openssl may be tested:

              echo already installed openssl (found with PATH environment)
              openssl ciphers -v
              openssl ciphers -V -ssl2
              openssl ciphers -V -ssl3
              openssl ciphers -V ALL
              openssl ciphers -V ALL:COMPLEMENTOFALL
              openssl ciphers -V ALL:eNULL:EXP

              echo own compiled and installed openssl
              /usr/local/openssl ciphers -v
              /usr/local/openssl ciphers -V -ssl2
              /usr/local/openssl ciphers -V -ssl3
              /usr/local/openssl ciphers -V ALL
              /usr/local/openssl ciphers -V ALL:COMPLEMENTOFALL
              /usr/local/openssl ciphers -V ALL:eNULL:EXP

        The difference should be obvious.
        Note, the commands using  "ALL:COMPLEMENTOFALL"  and  "ALL:eNULL:EXP"
        should return the same result.

    Testing Net::SSLeay

        As we want to test the separately installed  Net::SSLeay,  it is best
        to do it with  $0  itself:

              $0 +version

        we should see a line similar to follwong at the end of the output:
              Net::SSLeay   1.72  /usr/local/lib/x86_64-linux-gnu/perl/5.20.2/Net/SSLeay.pm

        Now check for supported (known) ciphers:

              $0 ciphers -V

        we should see lines similar to those of the last '/usr/local/openssl'
        call. However, it should contain more cipher lines.

    Stand-alone Executable

        Some people asked for a stand-alone executable (mainly for Windows).
        Even perl is a scripting language there are situations where a stand-
        alone executable would be nice, for example if the installed perl and
        its libraries are outdated, or if perl is missing at all.

        Currently (2016) there a at least following possibilities to generate
        a stand-alone executable:

          * perl with PAR::Packer module
              pp -C -c $0
              pp -C -c $0 -M Net::DNS -M Net::SSLeay -M IO::Socket \
                          -M Net::SSLinfo -M Net::SSLhello
              pp -C -c checkAllCiphers.pl
              pp -C -c checkAllCiphers.pl -M Net::DNS

          * ActiveState perl with its perlapp
              perlapp --clean $0
              perlapp --clean $0 -M Net::DNS -M Net::SSLeay -M IO::Socket \
                          -M Net::SSLinfo -M Net::SSLhello
              perlapp --clean checkAllCiphers.pl
              perlapp --clean checkAllCiphers.pl -M Net::DNS

          * perl2exe from IndigoSTar
              perl2exe $0
              perl2exe checkAllCiphers.pl

        For details  on building the executable,  for example how to include
        all required modules, please refer to the documentation of the tool.
           * http://search.cpan.org/~rschupp/PAR-Packer-1.030/lib/PAR/Packer.pm
           * http://docs.activestate.com/pdk/6.0/PerlApp.html
           * http://www.indigostar.com 

        Note that  pre-build executables (build by perlapp, perl2exe) cannot
        be provided due to licence problems.
        Also note that using stand-alone executable have not been tested the
        same way as the $0 itself. Use them at your own risk.



SEE ALSO

        * openssl(1), Net::SSLeay(1), Net::SSLhello, Net::SSLinfo, timeout(1)
        * http://www.openssl.org/docs/apps/ciphers.html
        * IO::Socket::SSL(1), IO::Socket::INET(1)


HACKER's INFO

    Note on SSL versions

        Automatically detecting the supported SSL versions of the underlaying
        system is a hard job and not always possible. Reasons could be:

        * used perl modules (Socket::SSL, Net::SSLeay) does not handle errors
          properly. Erros may be:
              invalid SSL_version specified at ... IO/Socket/SSL.pm
              Use of uninitialized value in subroutine entry at lib/IO/Socket/SSL.pm

          There're some workarounds implemented since version 15.11.15 .

        * the underlaying libssl does not support the version, which then may
          result in segmentation fault

        * the underlaying libssl is newer than the perl module and the module
          has not been reinstalled. This most often happens with  Net::SSLeay
          This can be detected with (see version numbers for Net::SSLeay):
              $0 +version

        * perl (in particular a used module, see above)  may bail out  with a
          compile error, like
              Can't locate auto/Net/SSLeay/CTX_v2_new.al in @INC ...

          There're some workarounds implemented since version 15.11.15 .

        We try to detect unsupported versions and disable them automatically,
        a warning like follwoing is shown then:
              **WARNING: SSL version 'SSLv2': not supported by openssl

        All such warnings look like:
              **WARNING: SSL version 'SSLv2': ...

        If problems occour with  SSL versions, following commands and options
        may help to get closer to the reason or can be used as workaround:
              $0 +version
              $0 +version --v
              $0 +version | grep versions
              $0 +version | grep 0x
              $0 +protocols your.tld
              $0 +protocols your.tld --no-rc

        Checking for SSL version is done at one place in the code, search for
              supported SSL versions

        However, there are some dirty hacks where  SSLv2 and SSLv3 is checked
        again.

    Using private libssl.so and libcrypt.so

        For all  cryptographic functionality  the libraries  installed on the
        system will be used. In particular perl's Net::SSLeay(1)  module, the
        system's  libssl.so and libcrypt.so  and the  openssl(1)  executable.

        It is possible to provide your own libraries, if the  perl module and
        the executable are  linked using  dynamic shared objects  (aka shared
        library, position independent code).
        The appropriate option is  --lib=PATH.

        On most systems these libraries are loaded at startup of the program.
        The runtime loader uses a preconfigured list of directories  where to
        find these libraries. Also most systems provide a special environment
        variable to specify  additional paths  to directories where to search
        for libraries, for example the  LD_LIBRARY_PATH environment variable.
        This is the default environment variable used herein.  If your system
        uses  another name it must be specified with the  --envlibvar=NAME 
        option, where  NAME  is the name of the environment variable.

    Understanding  --exe=PATH, --lib=PATH, --openssl=FILE

        If any of  --exe=PATH  or  --lib=PATH  is provided, the pragram calls
        ('exec') itself recursively with all given options, except the option
        itself. The environment variables  'LD_LIBRARY_PATH'  and 'PATH'  are
        set before executing as follows:
          * prepend  'PATH'  with all values given with  --exe=PATH
          * prepend  'LD_LIBRARY_PATH'  with all values given with --lib=PATH


        This is exactly, what X&Cumbersome Approach& below describes. So these
        option simply provide a shortcut for that.

        Note that  --openssl=FILE  is a full path to the  openssl  executable
        and will not be changed.  However, if it is a relative path, it might
        be searched for using the previously set  'PATH'  (see above).

        Note that  'LD_LIBRARY_PATH'  is the default.  It can be changed with
        the  --envlibvar=NAME  option.

        While  --exe  mainly impacts the  openssl(1) executable,  --lib  also
        impacts o-saft.pl itself, as it loads other shared libraries if found.

        Bear in mind that  all these options  can affect the behaviour of the
        openssl subsystem,  influencing both  which executable is called  and
        which shared libraries will be used.

        NOTE that no checks are done if the options are set proper. To verify
        the settings, following commands may be used:
          $0 --lib=YOU-PATH --exe=YOUE-EXE +version
          $0 --lib=YOU-PATH --exe=YOUE-EXE --v +version
          $0 --lib=YOU-PATH --exe=YOUE-EXE --v --v +version

        Why so many options?  Exactly as described above, these options allow
        the users to tune the behaviour of the tool to their needs.  A common
        use case is to enable the use of a separate openssl build independent
        of the openssl package used by the operating system.  This allows the
        user fine grained control over openssl's encryption suites  which are
        compiled/available, without affecting the core system.

    Caveats

        Depending on your system and the used modules and executables, it can
        be tricky to replace the configured shared libraries with own ones.
        Reasons are:
          a) the linked library name contains a version number,
          b) the linked library uses a fixed path,
          c) the linked library is searched at a predefined path,
          d) the executable checks the library version when loaded.

        Only the first one a) can be circumvented.  The last one d) can often
        be ignored as it only prints a warning or error message.

        To circumvent the "name with version number" problem try following:

        1) use  ldd(1)  (or a similar tool) to get the names used by openssl:

              ldd /usr/bin/openssl

        which returns something like:

              libssl.so.0.9.8 => /lib/libssl.so.0.9.8 (0x00007f940cb6d000)
              libcrypto.so.0.9.8 => /lib/libcrypto.so.0.9.8 (0x00007f940c7de000)
              libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f940c5d9000)
              libz.so.1 => /lib/x86_64-linux-gnu/libz.so.1 (0x00007f940c3c1000)
              libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f940c02c000)
              /lib64/ld-linux-x86-64.so.2 (0x00007f940cdea000)

        Here only the first two libraries are important.  Both,  libcrypto.so
        and libssl.so  need to be version "0.9.8" (in this example).

        2) create a directory for your libraries, i.e.:

              mkdir /tmp/dada

        3) place your libraries there, assuming they are:

              /tmp/dada/libssl.so.1.42
              /tmp/dada/libcrypto.so.1.42

        4) create symbolic links in that directory:

              ln -s libssl.so.1.42    libssl.so.0.9.8
              ln -s libcrypto.so.1.42 libcrypto.so.0.9.8

        5) test program with following option:

              $0 +libversion --lib=/tmp/dada
              $0 +list --v   --lib=/tmp/dada

          or:

              $0 +libversion --lib=/tmp/dada -exe=/path/to-openssl
              $0 +list --v   --lib=/tmp/dada -exe=/path/to-openssl

        6) start program with your options, i.e.:

              $0 --lib=/tmp/dada +ciphers

        This works if  openssl(1)  uses the same shared libraries as
        Net::SSLeay(1),  which most likely is the case.

        It's tested with Unix/Linux only. It may work on other platforms also
        if they support such an environment variable and the installed
        Net::SSLeay(1)  and  openssl(1)  are linked using dynamic shared
        objects.

        Depending on  compile time settings  and/or  the location of the used
        tool or lib, a warning like following may occur:

              WARNING: can't open config file: /path/to/openssl/ssl/openssl.cnf

        This warning can be ignored, usually as  req  or  ca  sub commands of
        openssl is not used here. 
        To fix the problem, either use  --openssl-cnf=FILE  option or set the
        the environment variable OPENSSL_CONF properly.

      Cumbersome Approach

        A more cumbersome approach to call  this program is to set  following
        environment variables in your shell:

              PATH=/tmp/dada-1.42/apps:$PATH
              LD_LIBRARY_PATH=/tmp/dada-1.42

      Windows Caveats

        I.g. the used libraries on Windows are libeay32.dll and ssleay32.dll.

        Windows also supports the LD_LIBRARY_PATH environment variable. If it
        does not work as expected with that variable, it might be possible to
        place the libs in the same directory as the  corresponding executable
        (which is found by the PATH environment variable).
# openssl.exe 1.0.0e needs: libeay32.dll, ssleay32.dll

    Using CGI mode

        This script can be used as  CGI application. Output is the same as in
        common CLI mode, using  'Content-Type:text/plain'.  Keep in mind that
        the used modules like  Net::SSLeay(1)  will write some debug messages
        on  STDERR instead  STDOUT.  Therefore multiple  --v  and/or  --trace 
        options behave slightly different.

        No additional external files like  RC-FILE  or  DEBUG-FILE  are read
        in CGI mode; they are silently ignored.
        Some options are disabled in CGI mode  because they are dangerous  or
        don't make any sense.

      WARNING

          There are  no  input data validation checks implemented herein. All 
          input data is url-decoded once and then used verbatim.
          More advanced checks must be done outside before calling this tool.

        It is not recommended to run this tool in CGI mode.
        You have been warned!

#       The only code necessary for CGI mode is encapsulated at the beginning,
#       see  'if ($me =~/\.cgi/){ ... }'.  Beside some minor additional regex
#       matches (mainly removing trailing   '=' and empty arguments) no other
#       code is needed. 
#

    Using user specified code

        There are some functions called within the program flow, which can be
        filled with any perl code.  Empty stubs of the functions are prepared
        in  o-saft-usr.pm.  See also  USER-FILE.

# Description about Program Code and Documentation
# It is not shown with +help but can be retrieved with: '$0 --help=ProgramCode
#
#    Program Code
#
#        First of all: the main goal is to have a tool to be simple for users.
#        It's not designed to be academic code or simple for programmers.
#
#        Also testing for various flaws in other tools and protocols could not
#        be done in a standarized generic way using well designed software but
#        mainly needs individual code for each check, and sometimes more worse
#        variants of the same code.
#        Please keep this in mind, before trying to unitise the code. 
#
#        Note:  following descriptions mainly uses the term "sub" (the perlish
#        term) when talking about functions, procedures, and/or methods.
#
#      Syntax style
#
#        Identation is 4 spaces. TABs would be the better solution, IMHO.
#        Unfortunately some repositories have issues with TABs,  so spaces are
#        used only. Sick.
#
#        Additional spacing is used to format the code for better human reada-
#        bility. There is no strict rule about this, it's just done as needed.
#
#        Empty lines (empty, without any space!) are used to group code blocks
#        logically. However, there is no strict rule about this too.
#
#        K&R-style curly brackets for subs and conditions are used.
#        K&R-style round brackets for subs and conditions are used (means that
#        definitions of subs, and calls of subs  do not use  spaces before the
#        opening bracket, while conditions use spaces).
#
#        Calls of subs are written in  K&R-style using round brackets, and the
#        perlisch way without round brackets. This may be unitised in future.
#
#        Short subs and conditions may be written in just one line.
#        Note: there is no need for each command in its one line, as debugging
#        on code level is rarely done.
#
#        subs are defined with number and type of parameters to have a minimal
#        syntax check at compile time.
#
#        The  code  mainly uses  'text enclosed in single quotes'  for program
#        internal strings such as hash keys, and uses "double quoted text" for
#        texts being printed. However, exceptions if obviously necessary ;-)
#        Strings used for  RegEx are always enclosed in single quotes.  Reason
#        is mainly to make searching texts a bit easier.
#
#      Code style
#
#        Global variables are used, see X&Variables& for details below.
#
#        Variables are declared at beginning of subs. I.g. we do not use local
#        or my declarations in blocks (there may be some exceptions).
#
#        The code tries to avoid if-else constructs as much as possible. If an
#        else condition is used, it is written in one line:   } else {  .
#        elsif is used in "borrowed" code only ;-)
#
#        Early return statements in subs are prefered, rather than complicated
#        and nested conditions. There are also goto statements in parsers, but
#        return statements are prefered.
#
#        Most code is seqential instead of using functions, except the code is
#        used multiple times. This may be changed in future ...
#        It is not intended to have OO-code,  even perl's  OO capabilities are
#        used when rational.
#
#      Code quality
#
#        The code is regulary analysed using "perlcritic" -a front-end command
#        line tool to the Perl::Critic module. As decribed above, this code is
#        not supposed to be academically correct.  Nevertheless, we follow the
#        recommendations given by perlcritic to make the most of it.
#        For details please see:  .perlcriticrc  and  contrib/critic.sh .
#
#      General
#
#        Exceptions are not used, there is no need for them.
#
#        In general, the code *must not* use any additional libraries. We know
#        that there exist infinite marvellous libraries and frameworks (called
#        modules in perl), which would make some programming simpler,  but one
#        of the main goals of this tool is that it  should work on  any system
#        with just the core language (i.e. perl) installed. We do not want any
#        additional dependency, in particular no dependency on versions beside
#        the core language.  Currently some perl modules are an exception, and
#        will be removed in future.
#
#        Perl's  'die()'  is used whenever an unrecoverable error occurs.  The
#        message printed will always start with '**ERROR: '.
#        warnings are printed using perl's  'warn()'  function and the message
#        always starts with '**WARNING: '.
#
#        All output is written to STDOUT.  However perl's 'die()' and 'warn()'
#        write on STDERR. Only debug messages inside $0 are written to STDERR.
#
#        All 'print*()' functions write to STDOUT directly.  They are slightly
#        prepared for using texts from  the configuration (%cfg, %checks),  so
#        these texts can be adapted easily (either with  OPTIONS  or in code).
#
#        Calling external programs uses 'qx()' rather than backticks or perl's
#        'system()' function.  Also note that it uses round brackets insted of
#        slashes to avoid confusion with RegEx.
#
#        The code flow often uses postfix conditions, means the  if-conditions
#        are written right of the command to be executed. This is done to make
#        the code better readable (not disturbed by conditions).
#
#        While  Net::SSLinfo  uses  Net::SSLeay(1), o-saft.pl itself uses only
#        IO::Socket::SSL(1). This is done 'cause we need some special features
#        here. However,  IO::Socket::SSL(1)  uses  Net::SSLeay(1)  anyways.
#
#        The code is most likely not thread-safe. Anyway, we don't use them.
#
#        For debugging the code, the  --trace  option can be used. See  DEBUG 
#        section below for more details. Be prepared for a lot of output!
#
#      Comments
#
#        Following comments are used in the code:
#
#          # TODO:       Parts not working perfect, needs to be changed.
#          # FIXME:      Program code known to be buggy, needs to be fixed.
#          #!#           Comments not to be removed in compressed code.
#          #?            Description of sub.
#          #|            Code sections (documents program flow).
#          ##            Comments used by third-party programs  (for example:
#                        contrib/gen_standalone.sh, perlcritic).
#          # func        name of sub behind the closing bracket of sub
#
#        Comments usually precede the code line(s) or are placed at end of the
#        code line which they belong too. If the comments are placed after the
#        code line which they belong too, the lines are idented.
#
#      Variables
#
#        As explained above, global variables are used to avoid definitions of
#        complex subs with various parameters.
#
#        Most subs use global variables (even if they are defined in main with
#        'my'). These variables are mainly: @DATA, @results, %cmd, %data, %cfg,
#        %checks, %ciphers, %prot, %text.
#
#        Variables defined with 'our' can be used in   o-saft-dbx.pm   and
#        o-saft-usr.pm.
#
#        For a detailed description of the used variables, please refer to the
#        text starting at the line  '#!# set defaults'.
#
#      Function names
#
#        Some rules used for sub names:
#
#          check*        Functions which perform some checks on data.
#          print*        Functions which print results.
#          get_*         Functions to get values from internal data structure.
#          _<function_name>    Some kind of helper (internal) function.
#          _trace*
#          _y*           Print information when  --trace  is in use.
#          _v*print      Print information when  --v  is in use.
#
#        Function (sub) definitions are followed by a short description, which
#        is just one line right after the 'sub' line.  Such lines always start
#        with  '#?'  (see below how to get an overview).
#
#        Subs are ordered to avoid forward declarations as much as possible.
#
#      Code information
#
#        Examples to get an overview of perl functions (sub):
#          egrep '^(sub|\s*#\?)' $0
#
#        Same a little bit formatted, see  +traceSUB  command.
#
#        Examples to get an overview of programs workflow:
#          egrep '(^#\|\s|\s\susr_)' $0
#
#        Following to get perl's variables for checks:
#          $0 +check localhost --trace-key \
#          | awk -F'#' '($2~/^ /){a=$2;gsub(" ","",a);next}(NF>1){printf"%s{%s}\n",a,$2}' \
#          | tr '%' '$'
#
#      Debugging, Tracing
#
#        Most functionality for trace, debug or verbose output is encapsulated
#        in functions (see X&Function names& above). These subs are defined as
#        empty stubs in o-saft.pl. The real definitions are in  o-saft-dbx.pm,
#        which is loaded on demand when any  --trace*  or --v  option is used.
#        As long as these options are not used,  o-saft.pl  works without
#        o-saft-dbx.pm.
#
#        Trace messages always start with  '#O-Saft :'.
#        Debug messages always start with  '#o-saft.pl::'.
#        Following formats are used:
#          #o-saft.pl:: some data           - output from o-saft.pl's main
#          #o-saft.pl::subfunc(){           - inital output in subfunc
#          #o-saft.pl::subfunc: some data   - some output in subfunc
#          #o-saft.pl::subfunc() = result } - result output of subfunc
#        However, these rules are implemented very lazy.
#
#        Note: in contrast to the name of the RC-FILE, the name  o-saft-dbx.pm
#        is hard-coded.
#
#      Abstract program flow
#          check special options and command (+exec, +cgi, --envlibvar)
#          read RC-FILE, DEBUG-FILE and USER-FILE if necessary
#          initialize internal data structure
#          scan options and arguments
#          perform commands without connection to target
#          loop over all specified targets
#              print DNS stuff
#              open connction and retrive information
#              print ciphers
#              print protocols
#              print information
#              print checks
#
#      Program flow
#
#        As explained in the documentation (please see +help) there are mainly
#        3 types of `checks':
#          +info    - getting as much information as possible about the target
#                     its certificate and the connection
#          +cipher  - checking for supported ciphers by the target
#          +check   - doing all the checks based on +info and +cipher
#
#        Any information is collected using  Net::SSLinfo and stored in %data.
#        All information according ciphers is collected directly and stored in
#        @results. Finally, when performing the checks, these informations are
#        used and compared to expected well know values.  The results of these
#        checks are stored in  %checks.
#        Then all information from %data and %checks is printed by just loop-
#        ing through these hashes.
#
#        Information is just collected using  Net::SSLinfo  and then printed.
#        Checks are performed on provided data by  Net::SSLinfo  and specified
#        conditions herein.  Most checks are done in functions  'check*',  see
#        above.
#        Some checks depend on other checks,  so check functions may be called
#        anywhere to solve dependencies. To avoid multiple checks,  each check
#        function sets and checks a flag if already called, see  $cfg{'done'}.
#
#      Documentation
#
#        All documentation of code details is  close to the corresponding code
#        lines. Some special comment lines are used, see  X&Comments&  above.
#        Note: comments describe *why* the code is written in some way  (means
#        the logic of the code),  and not  *what* the code does (which is most
#        likely obvious).
#
#        All documentation for the user is written in  plain ASCII text format
#        at end of this file  o-saft-usr.pm.
#
#        All documentation was initially written in perl's POD format. After 2
#        years of development, it seems that POD wasn't the best decission, as
#        it makes extracting information from documentation complicated, some-
#        times. Using POD is also a huge performance penulty on all platforms.


DEBUG

    Debugging, Tracing

        Following  options and commands  are useful for hunting problems with
        SSL connections and/or this tool. Note that some options can be given
        multiple times to increase amount of listed information. Also keep in
        mind that it's best to specify  --v  as very first argument.

        Note that the file  o-saft-dbx.pm  is required,  if any  --trace*  or
        --v   option is used.

      Commands

          * +dump
          * +libversion
          * +s_client
          * +todo
          * +version

      Options

          * --v
          * --v--
          * --trace
          * --trace-arg
          * --trace-cmd
          * --trace-key

        Empty or undefined strings are written as  '<<undefined>>'  in texts.
        Some parameters, in particular those of  HTTP responses,  are written
        as  '<<response>>'.  Long parameter lists are abbreviated with '...'.

      Output

        When using  --v  and/or  --trace  options,  additional output will be
        prefixed with a  '#'  (mainly as first, left-most character.
        Following formats are used:

           #<space>
             Additional text for verbosity (--v options).

           #[variable name]<TAB>
             Internal variable name (--trace-key options).

           #o-saft.pl::
           #Net::SSLinfo::
             Trace information for --trace  options.

           #{
             Trace information from  NET::SSLinfo  for  --trace  options.
             These are data lines in the format:
              #{ variable name : value #}

             Note that 'value'  here can span multiple lines and ends with:
              #}


EXAMPLES

        ($0 in all following examples is the name of the tool)

    General

          $0 +cipher some.tld
          $0 +info   some.tld
          $0 +check  some.tld
          $0 +quick  some.tld
          $0 +help=commands
          $0 +certificate  some.tld
          $0 +fingerprint  some.tld 444
          $0 +after +dates some.tld
          $0 +version
          $0 +version --v
          $0 +list
          $0 +list    --v

    Some specials

        * Get an idea how messages look like
          $0 +check --cipher=RC4 some.tld

        * Check for Server Name Indication (SNI) usage only
          $0 +sni some.tld

        * Check for SNI and print certificate's subject and altname
          $0 +sni +cn +altname some.tld

        * Check for all SNI, certificate's subject and altname issues
          $0 +sni_check some.tld

        * Only print supported ciphers
          $0 +cipher --enabled some.tld

        * Only print unsupported ciphers
          $0 +cipher --disabled some.tld

        * Test for a specific ciphers
          $0 +cipher --cipher=ADH-AES256-SHA some.tld

        * Test all ciphers, even if not supported by local SSL implementation
          $0 +cipherall some.tld
          $0 +cipherall some.tld --range=full
          checkAllCiphers.pl example.tld --range=full --v

        * Show supported (enabled) ciphers with their DH parameters:
          $0 +cipher-dh some.tld

        * Test using a private libssl.so, libcrypto.so and openssl
          $0 +cipher --lib=/foo/bar-1.42 --exe=/foo/bar-1.42/apps some.tld

        * Test using a private openssl
          $0 +cipher --openssl=/foo/bar-1.42/openssl some.tld

        * Test using a private openssl also for testing supported ciphers
          $0 +cipher --openssl=/foo/bar-1.42/openssl --force-openssl some.tld

# score will be removed, so don't anounce it
#        * Show current score settings
#          $0 --help=score
#
#        * Change a single score setting
#          $0 --cfg-score=http_https=42   +check some.tld
#
#        * Use your private score settings from a file
#          $0 --help=score > magic.score
#                   edit as needed: magic.score
#          $0 --cfg-score    magic.score  +check some.tld

        * Use your private texts in output
          $0 +check some.tld --cfg-text=desc="my special description"

        * Use your private texts from RC-FILE
          $0 --help=cfg-text >> .o-saft.pl
            edit as needed: .o-saft.pl
          $0 +check some.tld

        * Use your private hint texts in output
          $0 +check some.tld --cfg-hint=renegotiation="my special hint text"
#
#        * Use your private score settings from a file
#          $0 --help=score > magic.score

        * Get the certificate's Common Name for a bunch of servers:
          $0 +cn example.tld some.tld other.tld
          $0 +cn example.tld some.tld other.tld --showhost --no-header

        * Generate simple parsable output
          $0 --legacy=quick --no-header +info  some.tld
          $0 --legacy=quick --no-header +check some.tld
          $0 --legacy=quick --no-header --trace-key +info  some.tld
          $0 --legacy=quick --no-header --trace-key +check some.tld

        * Generate simple parsable output for multiple hosts
          $0 --legacy=quick --no-header --trace-key --showhost +check some.tld other.tld

        * Just for curiosity
          $0 some.tld +fingerprint --format=raw
          $0 some.tld +certificate --format=raw | openssl x509 -noout -fingerprint

    Special for hunting problems with connections etc.

        * Do not read RC-FILE .o-saft.pl
          $0 +info some.tld --no-rc

        * Show command line argument processing
          $0 +info some.tld --trace-arg

        * Simple tracing
          $0 +cn   some.tld --trace
          $0 +info some.tld --trace

        * A bit more tracing
          $0 +cn   some.tld --trace --trace

        * Show internal variable names in output
          $0 +info some.tld --trace-key

        * Show internal argument processeing
          $0 +info --trace-arg some.tld

        * Show internal control flow and timing
          $0 +info some.tld --trace-time

        * List checked ciphers
          $0 +cipher some.tld --v --v

        * List checked ciphers one per line
          $0 +cipher some.tld --v --v --v

        * Show processing of ciphers
          $0 +cipher some.tld --v --v --v --v

        * Show values retrieved from target certificate directly
          $0 +info some.tld --no-cert --no-cert --no-cert-text=Value-from-Certificate

        * Show certificate CA verifications
          $0 some.tld +chain_verify +verify +error_verify +chain

        * Avoid most performance and timeout problems (don't use  --v)
          $0 +info some.tld --no-cert --no-dns --no-http --no-openssl --no-sni

#begin --v --v
.raw nerobeg
sretset rof tidua LSS PSAWO  -  "tfaS-O"   
retseT reuf tiduA LSS PSAWO  -  "tfaS-O"   
:nnawdnegri nnad sib ,elieW enie sad gnig oS
..wsu ,"haey-lss" ,"agoy-lss" :etsiL red fua dnats -reteaps reibssieW
eretiew  raap nie-  nohcs se tnha nam  ,ehcuS eid nnageb os ,nebegrev
nohcs dnis nemaN ednessap eleiV  .guneg "giffirg"  thcin reba sad raw
gnuhciltneffeoreV enie reuF .noisrevsgnulkciwtnE red emaN red tsi saD
. loot LSS rehtona tey -  "lp.tsaey"   :resseb nohcs tsi sad
,aha ,tsaey -- efeH -- reibssieW -- .thcin sad tgnilk srednoseb ,ajan
eigeRnegiE nI resworB lSS nIE redeiW  -  "lp.reibssiew"   
:ehan gal se ,nedrew emaN "regithcir" nie hcod nnad se etssum
hcan dnu hcaN  .edruw nefforteg setsre sla "y" sad liew ,"lp.y" :eman
-ietaD nie snetsednim  ,reh emaN nie etssum sE .slooT seseid pytotorP
retsre nie  nohcs hcua  dnatstne iebaD  .tetsokeg reibssieW eleiv dnu
nednutS eginie nnad hcim tah esylanA eiD .)dnis hcon remmi dnu( neraw
nedeihcsrev rhes esiewliet eis muraw ,nednifuzsuareh dnu nehetsrev uz
)noitpO "*=ycagel--"  eheis( slooT-tseT-LSS reredna releiv essinbegrE
nehcildeihcsretnu eid hcusreV mieb  dnatstne looT  meseid uz eedI eiD

)-: ti dnatsrednu :laog txeN .eno neddih eht ,ti tog uoY
#end --v


ATTRIBUTION

        Based on ideas (in alphabetical order) of:

        * cnark.pl, SSLAudit.pl sslscan, ssltest.pl, sslyze.py, testssl.sh

        * O-Saft - OWASP SSL advanced forensic tool
            Thanks to Gregor Kuznik for this title.

        * +cipherraw and some proxy functionality implemented by Torsten Gigler.

        * For re-writing some docs in proper English, thanks to Robb Watson.

        * Code to check heartbleed vulnerability adapted from
            Steffen Ullrich (08. April 2014):
            https://github.com/noxxi/p5-scripts/blob/master/check-ssl-heartbleed.pl

        * Colouration inspired by https://testssl.sh/ .


VERSION

        @(#) $VERSION

AUTHOR

        31. July 2012 Achim Hoffmann (at) sicsec de

        Project Home: https://www.owasp.org/index.php/O-Saft


# TODO must be last section
TODO

#        openssl (nicht bei 0.9.8, bei 1.0.1*) -legacy_renegotiation
#        SSLCertScanner.exe http://www.xenarmor.com/network-ssl-certificate-scanner.php ansehen

        * new features
          ** client certificate
          ** some STRATTLS need : HELP STARTTLS HELP as output of HELPs are different
          ** support: PCT protocol
          ** Checking fallback from TLS 1.1 to TLS 1.0 (see ssl-cipher-check.pl)
          ** Minimal encryption strength: weak encryption (40-bit) (TestSSLServer.jar)
          ** check dynamic HTTP Public Key Pinning (HPKP)

        * missing checks
          ** SSL_honor_cipher_order => 1
          ** implement TLSv1.2 checks
          ** DNSEC and TLSA
          ** checkcert(): KeyUsage, keyCertSign, BasicConstraints
          ** DV and EV miss some minor checks; see checkdv() and checkev()
          ** +constraints does not check +constraints in the certificate of
             the certificate chain.
          ** TR-03116-4: does not check data in certificate chain
          ** RFC 7525: does not check data in certificate chain
          ** RFC 7525: 3.2.  Strict TLS (for STARTTLS)
          ** RFC 7525: 3.4.  TLS Session Resumption (session ticket must be
             authenticated and encrypted)
          ** RFC 7525: 3.6.  Server Name Indication (more reliable check)
          ** RFC 7525: 4.3.  Public Key Length (need more reliable check)
          ** RFC 7525: 6.2.  AES-GCM
          ** RFC 7525: 6.3.  Forward Secrecy
          ** RFC 7525: 6.4.  Diffie-Hellman Exponent Reuse

        * vulnerabilities
          ** complete TIME, BREACH check
          ** BEAST more checks, see: http://www.bolet.org/TestSSLServer/

        * verify CA chain:
          ** Net::SSLinfo.pm implement verify*
          ** implement +check_chain (see Net::SSLinfo.pm implement verify* also)
          ** implement +ca = +verify +chain +rootcert +expired +fingerprint

        * postprocessing
          Remove all options for output formatting. Use a "postprocess" script
          instead.
          ** scoring
             implement score for PFS; lower score if not all ciphers support PFS
             make clear usage of score from %checks
          ** write postprocessor for tabular data, like
             ssl-cert-check -p 443 -s mail.google.com -i -V

        * Net::SSLeay
          ** remove all warn() as Net::SSLeay should be silent
          ** Net::SSLinfo.pm Net::SSLeay::ctrl()  sometimes fails, but doesn't
             return error message
          ** Net::SSLeay::CTX_clear_options()
             Need to check the difference between the  SSL_OP_LEGACY_SERVER_CONNECT  and
             SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION;  see also SSL_clear_options().
             see https://www.openssl.org/docs/ssl/SSL_CTX_set_options.html
          ** Net::SSLeay::do_ssl_close()  does not realy work

        * Windows
          ** Unicode:
             try: cmd /K chcp 65001
             or:  chcp 65001
             or:  reg add hklm\system\currentcontrolset\control\nls\codepage -v oemcp -d 65001
          ** perl
             perl 5.10.x from PortableApps does not work, cause it misses
             IO/Socket/SSL.pm, however, checkAllCiphers.pl works.
             perl from older PortableApps/xampp (i.e. 1.7.x) does not work, cause
             IO/Socket/SSL.pm is too old (1.37).
          ** Windows
             on Windows print of strings > 32k does not work.
             Ugly workaround using --v implemented in o-saft-man.pm only.

        * internal
          ** use qr() for defining regex, see $cfg{'regex'}
          ** print_line() hase ugly code for legacy=cipher
          ** "Label" texts are defined twice: o-saft.pl and Net::SSLeay
          ** make a clear concept how to handle +CMD whether they report
             checks or informations (aka %data vs. %check_*)
             currently (2016) each single command returns all values
          ** client certificates not yet implemented in _usesocket() _useopenssl(),
             see t.client-cert.txt
          ** (nicht wichtig, aber sauber programmieren)
             _get_default(): Net::SSLinfo::default() benutzen

END # mandatory to keep some grep happy
