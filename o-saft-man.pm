#!/usr/bin/perl -w

### This  software is licensed under GPLv2. Please see o-saft.pl for details.

package main;   # ensure that main:: variables are used

binmode(STDOUT, ":unix");
binmode(STDERR, ":unix");

my  $man_SID= "@(#) o-saft-man.pm 1.9a 15/01/15 00:42:42";  # our SCCS id
our $parent = (caller(0))[1] || "O-Saft";# filename of parent, O-Saft if no parent
    $parent =~ s:.*/::;
our $wer    = (caller(1))[1];           # tricky to get filename of myself when called from BEGIN
our $ich    = $ich;
    $ich    = "o-saft-man.pm" if (! defined $ich); # sometimes it's empty :-((
    $ich    =~ s:.*/::;
    $wer    = $ich if -e $ich;          # check if exists, otherwise use what caller() provided
if (! defined $wer) { # still nothing found, last resort: parent
    $wer    = (caller(0))[1]; # parent;
    $wer    =~ s#/[^/\\]*$##; # path of parent
    $wer    .= "/$ich";       # append myself
    print "**WARNING: no '$wer' found" if ! -e $wer;
}
our $version= _VERSION() || "$man_SID"; # version of parent, myself if empty
my  $skip   = 1;
our $egg    = "";
our @DATA;
if (open(DATA, $wer)) {
    # If this module is used in parent's BEGIN{} section, we don't have any
    # file descriptor, in particular nothing beyond __DATA__. Hence we need
    # to read the file --this one-- manually, and strip off anything before
    # __DATA__. Stripping could be done using perl's  grep, join and splice
    # functions, but using a simple loop is more readable.
    # Preformat plain text with markup for further simple substitutions. We
    # use a modified (& instead of < >) POD markup as it is easy to parse.
    # &  was choosen 'cause it rarely appears in texts and is not a meta
    # character in any of the supported  output formats (text, wiki, html),
    # and also causes no problems inside regex.
    while (<DATA>) {
        $skip = 2, next if (/^#begin/);
        $skip = 0, next if (/^#end/);
        $skip = 0, next if (/^__DATA__/);
        $egg .= $_,next if ($skip eq 2);
        next if ($skip ne 0);
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
        if (!m/^(?:=|S&|\s+\$0)/) { # no markup in example lines and already marked lines
            s!(\s)((?:\+|--)[^,\s).]*)([,\s).])!$1I&$2&$3!g; # markup commands and options
                # FIXME: fails for something like:  --opt="foo bar"
        }
        s/((?:Net::SSLeay|ldd|openssl|timeout|IO::Socket(?:::SSL|::INET)?)\(\d\))/L&$1&/g;
        s/((?:Net::SSL(?:hello|info)|o-saft(?:-dbx|-man|-usr|-README)(?:\.pm)?))/L&$1&/g;
        s/  (L&[^&]*&)/ $1/g;
        s/(L&[^&]*&)  /$1 /g;
            # If external references are enclosed in double spaces, we squesze
            # leading and trailing spaces 'cause additional characters will be
            # added later (i.e. in man_help()). Just pretty printing ...
        if (m/^ /) {                    # add internal links; quick&dirty list here
            s/ ((?:DEBUG|RC|USER)-FILE)/ X&$1&/g;
            s/ (CONFIGURATION (?:FILE|OPTIONS))/ X&$1&/g;
            s/ (COMMANDS|OPTIONS|RESULTS|CHECKS|OUTPUT) / X&$1& /g;
            s/ (CUSTOMIZATION|SCORING|LIMITATIONS|DEBUG|EXAMPLES) / X&$1& /g;
        }
        s#\$VERSION#$version#g;         # add current VERSION
        s# \$0# $parent#g;              # my name
        push(@DATA, $_);
    }
    close(DATA);
}
our $\ = "";

## definitions: more documentations as data
## -------------------------------------
our %man_text = (
    # short list of used terms and acronyms, always incomplete ...
    'glossar' => {
        'AA'        => "Attribute Authority",
        'AAD'       => "additional authenticated data",
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
        'ASN.1'     => "Abstract Syntax Notation One",
        'BDH'       => "Bilinear Diffie-Hellman",
        'BEAST'     => "Browser Exploit Against SSL/TLS",
        'BER'       => "Basic Encoding Rules",
        'Blowfish'  => "symmetric block cipher",
        'BREACH'    => "Browser Reconnaissance & Exfiltration via Adaptive Compression of Hypertext (a variant of CRIME)",
                    #   http://www.breachattack.com/
        'CAMELLIA'  => "Encryption algorithm 128 bit (by Mitsubishi and NTT)",
        'CAST-128'  => "Carlisle Adams and Stafford Tavares, block cipher",
        'CAST5'     => "alias for CAST-128",
        'CAST-256'  => "Carlisle Adams and Stafford Tavares, block cipher",
        'CAST6'     => "alias for CAST-256",
        'cipher suite'  => "cipher suite is a named combination of authentication, encryption, and message authentication code algorithms",
        'CA'        => "Certificate Authority (aka root CA)",
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
        'CRIME'     => "Compression Ratio Info-leak Made Easy (Exploit SSL/TLS)",
        'CRL'       => "Certificate Revocation List",
        'CSP'       => "Certificate Service Provider",
        'CSP '      => "Critical Security Parameter (used in FIPS 140-2)",
        'CSR'       => "Certificate Signing Request",
        'CP'        => "Certificate Transparency",
        'CTL'       => "Certificate Trust Line",
        'CTR'       => "Counter Mode (sometimes: CM; block cipher mode)",
        'CTS'       => "Cipher Text Stealing",
        'CWC'       => "CWC Mode (Carter-Wegman + CTR mode; block cipher mode)",
        'DAA'       => "Data Authentication Algorithm",
        'DAC'       => "Data Authentication Code",
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
        'DANE'      => "DNS-based Authentication of Named Entities",
        'DDH'       => "Decisional Diffie-Hellman (Problem)",
        'DEA'       => "Data Encryption Algorithm (sometimes a synonym for DES)",
        'DECIPHER'  => "synonym for decryption",
        'DER'       => "Distinguished Encoding Rules",
        'DH'        => "Diffie-Hellman",
        'DHE'       => "Diffie-Hellman ephemeral", # historic acronym, often used, mainly in openssl
        'DLIES'     => "Discrete Logarithm Integrated Encryption Scheme",
        'DN'        => "Distinguished Name",
        'DPA'       => "Dynamic Passcode Authentication (see CAP)",
        'DRBG'      => "Deterministic Random Bit Generator",
        'DSA'       => "Digital Signature Algorithm",
        'DSS'       => "Digital Signature Standard",
        'DTLS'      => "Datagram TLS",
        'DTLSv1'    => "Datagram TLS 1.0",
        'DV'        => "Domain Validation",
        'DV-SSL'    => "Domain Validated Certificate",
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
        'EDE'       => "Encryption-Decryption-Encryption",
        'EDH'       => "Ephemeral Diffie-Hellman", # official acronym
        'EGB'       => "Entropy Gathering Daemon",
        'ELB'       => "Encrypt Last Block",
        'ElGamal'   => "asymmetric block cipher",
        'ENCIPHER'  => "synonym for encryption",
        'EME'       => "Encoding Method for Encryption",
        'ESP'       => "Encapsulating Security Payload",
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
        'HSTS'      => "HTTP Strict Transport Security",
        'HTOP'      => "HMAC-Based One-Time Password",
        'IAPM'      => "Integrity Aware Parallelizable Mode (block cipher mode of operation)",
        'ICM'       => "Integer Counter Mode (alias for CTR)",
        'IDEA'      => "International Data Encryption Algorithm (by James Massey and Xuejia Lai)",
        'IFC'       => "Integer Factorization Cryptography",
        'ISAKMP'    => "Internet Security Association and Key Management Protocol",
        'IV'        => "Initialization Vector",
        'JSSE'      => "Java Secure Socket Extension",
        'KEA'       => "Key Exchange Algorithm (alias for FORTEZZA-KEA)",
        'KEK'       => "Key Encryption Key",
        'KSK'       => "Key Signing Key", # DNSSEC
        'LM hash'   => "LAN Manager hash aka LanMan hash",
        'LFSR'      => "Linear Feedback Shift Register",
        'Lucky 13'  => "Break SSL/TLS Protocol",
        'MARS'      => "",
        'MAC'       => "Message Authentication Code",
        'MCF'       => "Modular Crypt Format",
        'MEE'       => "MAC-then-Encode-then-Encrypt",
        'MEK'       => "Message Encryption Key",
        'MDC2'      => "Modification Detection Code 2 aka Meyer-Schilling",
        'MDC-2'     => "same as MDC2",
        'MD2'       => "Message Digest 2",
        'MD4'       => "Message Digest 4",
        'MD5'       => "Message Digest 5",
        'MGF'       => "Mask Generation Function",
        'MISTY1'    => "block cipher algorithm",
        'MQV'       => "Menezes-Qu-Vanstone (authentecated key agreement",
        'NTLM'      => "NT Lan Manager. Microsoft Windows challenge-response authentication method.",
        'NPN'       => "Next Protocol Negotiation",
        'Neokeon'   => "symmetric block cipher algorithm",
        'NSS'       => "Network Security Services",
        'nonce'     => "(arbitrary) number used only once",
        'NULL'      => "no encryption",
        'NUMS'      => "nothing up my sleeve numbers",
        'OAEP'      => "Optimal Asymmetric Encryption Padding",
        'OFB'       => "Output Feedback",
        'OCB'       => "Offset Codebook Mode (block cipher mode of operation)",
        'OCB1'      => "same as OCB",
        'OCB2'      => "improved OCB aka AEM",
        'OCB3'      => "improved OCB2",
        'OFBx'      => "Output Feedback x bit mode",
        'OID'       => "Object Identifier",
        'OTP'       => "One Time Pad",
        'OCSP'      => "Online Certificate Status Protocol",
        'OCSP stapling' => "formerly known as: TLS Certificate Status Request",
        'OMAC'      => "One-Key CMAC, aka CBC-MAC",
        'OMAC1'     => "same as CMAC",
        'OMAC2'     => "same as OMAC",
        'OV'        => "Organisational Validation",
        'OV-SSL'    => "Organisational Validated Certificate",
        'P12'       => "see PKCS#12",
        'P7B'       => "see PKCS#7",
        'PCT'       => "Private Communications Transport",
        'PACE'      => "Password Authenticated Connection Establishment",
        'PAKE'      => "Password Authenticated Key Exchange",
        'PBE'       => "Password Based Encryption",
        'PBKDF2'    => "Password Based Key Derivation Function",
        'PC'        => "Policy Constraints (certificate extension)",
        'PCBC'      => "Propagating Cipher Block Chaining",
        'PCFB'      => "Periodic Cipher Feedback Mode",
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
        'PM'        => "Policy Mappings (certificate extension)",
        'PMAC'      => "Parallelizable MAC (by Phillip Rogaway)",
        'Poly1305-AES'  => "MAC (by D. Bernstein)",
        'POP'       => "Proof of Possession",
        'Poodle'    => "Padding Oracle On Downgraded Legacy Encryption",
        'PRF'       => "pseudo-random function",
        'PRNG'      => "pseudo-random number generator",
        'PSK'       => "Pre-shared Key",
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
        'Rijndael'  => "symmetric block cipher algorithm",
        'RIPEMD'    => "RACE Integrity Primitives Evaluation Message Digest",
        'RMAC'      => "block cipher authentication mode",
        'RNG'       => "Random Number Generator",
        'ROT-13'    => "see XOR",
        'RTP'       => "Real-time Transport Protocol",
        'RSA'       => "Rivest Sharmir Adelman (public key cryptographic algorithm)",
        'RSS-14'    => "Reduced Space Symbology, see GS1",
        'RTN'       => "Routing transit number",
        'SA'        => "Subordinate Authority (aka Subordinate CA)",
        'SAFER'     => "Secure And Fast Encryption Routine, block cipher",
        'Salsa20'   => "stream cipher",
        'SAM'       => "syriac abbreviation mark",
        'SAN'       => "Subject Alternate Name",
        'SBCS'      => "single-byte character set",
        'SCEP'      => "Simple Certificate Enrollment Protocol",
        'SCSU'      => "Standard Compression Scheme for Unicode (compressed UTF-16)",
        'SCSV'      => "Signaling Cipher Suite Value",
        'SCVP'      => "Server-Based Certificate Validation Protocol",
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
        'Skipjack'  => "block cipher encryption algorithm specified as part of the Fortezza",
        'Snefu'     => "hash function",
        'SNI'       => "Server Name Indication",
        'SNOW'      => "word-based synchronous stream ciphers (by Thomas Johansson and Patrik Ekdahl )",
        'SPDY'      => "Google's application-layer protocol on top of SSL",
        'SPN'       => "Substitution-Permutation Network",
        'Square'    => "block cipher",
        'SRP'       => "Secure Remote Password protocol",
        'SRTP'      => "Secure RTP",
        'SSL'       => "Secure Sockets Layer",
        'SSLv2'     => "Secure Sockets Layer Version 2",
        'SSLv3'     => "Secure Sockets Layer Version 3",
        'SSP'       => "Security Support Provider",
        'SSPI'      => "Security Support Provider Interface",
        'SST'       => "Serialized Certificate Store format",
        'STS'       => "Strict Transport Security",
        'STS '      => "Station-to-Station protocol",
        'TACK'      => "Trust Assertions for Certificate Keys",
        'TCB'       => "Trusted Computing Base",
        'TDEA'      => "Tripple DEA",
        'TEA'       => "Tiny Encryption Algorithm",
        'TEK'       => "Traffic Encryption Key",
        'Tiger'     => "hash function",
        'TIME'      => "Timing Info-leak Made Easy (Exploit SSL/TLS)",
#        'TIME'      => "A Perfect CRIME? TIME Will Tell",
        'Threefish' => "hash function",
        'TMAC'      => "Two-Key CMAC, variant of CBC-MAC",
        'TOCTOU'    => "Time-of-check, time-of-use",
        'TOFU'      => "Trust on First Use",
        'TR-02102'  => "Technische Richtlinie 02102 (des BSI)",
        'TSK'       => "TACK signing key",
        'TSP'       => "trust-Management Service Provider",
        'TLS'       => "Transport Layer Security",
        'TLSA'      => "TLS Trus Anchors",
        'TLSv1'     => "Transport Layer Security version 1",
        'TSK'       => "Transmission Security Key",
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
        'XCBC'      => "variant of CMAC",
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

    # RFC 2246:  TLS Version 1
    # RFC 4346:  TLS Version 1.1
    # RFC 5246:  TLS Version 1.2  http://tools.ietf.org/html/rfc5346
    # RFC 2412: OAKLEY Key Determination Protocol (PFS - Perfect Forward Secrec')
    #           alle *DH* sind im Prinzip PFS.
    #           wird manchmal zusaetzlich mit DHE bezeichnet, wobei E für ephemeral
    #           also flüchtige, vergängliche Schlüssel steht
    #           D.H. ECDHE_* und DHE_* an den Anfang der Cipherliste stellen, z.B.
    #                TLS_ECDHE_RSA_WITH_RC4_128_SHA
    #                TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    #                TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    #                TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA 
    #           http://en.wikipedia.org/wiki/Perfect_forward_secrecy
    # RFC 2818: ? (Namenspruefung)
    # RFC 2712: TLSKRB: Addition of Kerberos Cipher Suites to Transport Layer Security (TLS)
    # RFC 2986: PKCS#10
    # RFC 5967: PKCS#10
    # RFC 3268:  TLSAES: Advanced Encryption Standard (AES) Ciphersuites for Transport Layer Security (TLS)
    # RFC 5081: TLSPGP: Using OpenPGP Keys for Transport Layer Security (TLS) Authentication
    # RFC 4279:  TLSPSK: Pre-Shared Key Ciphersuites for Transport Layer Security (TLS)
    # RFC 4492:  TLSECC: Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS)
    # RFC 3749: TLS Compression Method http://tools.ietf.org/html/rfc3749
    # RFC 3943: TLS Protocol Compression Using Lempel-Ziv-Stac (LZS) http://tools.ietf.org/html/rfc3943
    # RFC 3268:  TLS Version 1 AES
    # RFC 4132:  TLS Version 1 Camellia
    # RFC 4162: TLS Version 1 SEED
    # RFC 3546: TLS Extensions
    # RFC 4366: TLS Extensions
    #               AKID - authority key identifier
    #               Server name Indication (SNI): server_name
    #               Maximum Fragment Length Negotiation: max_fragment_length
    #               Client Certificate URLs: client_certificate_url
    #               Trusted CA Indication: trusted_ca_keys
    #               Truncated HMAC: truncated_hmac
    #               Certificate Status Request (i.e. OCSP stapling): status_request
    #               Error Alerts
    # RFC 5764: TLS Extensions SRTP
    # RFC 4366: OCSP stapling (http://en.wikipedia.org/wiki/OCSP_stapling)
    # RFC 6066: OCSP stapling (http://en.wikipedia.org/wiki/OCSP_stapling) TLS Certificate Status Request
    # RFC 6066: TLS Extensions: Extension Definitions
    #                PkiPath
    # RFC 6066: TLS Extensions: Heartbeat https://tools.ietf.org/html/rfc6520
    # RFC 4749: TLS Compression Methods
    # RFC 5077: TLS session resumption
    # RFC 4347: DTLS Datagram TLS
    # RFC 2246: TLS protocol version 1.0 http://tools.ietf.org/html/rfc2246
    # RFC 6101: SSL protocol version 3.0 http://tools.ietf.org/html/rfc6101
    # RFC 6460: ?
    # RFC 6125: Representation and Verification of Domain-Based Application Service Identity within Internet Public Key Infrastructure Using X.509 (PKIX) Certificates in the Context of Transport Layer Security (TLS)
    # RFC 4210: X509 PKI Certificate Management Protocol (CMP)
    # RFC 3739: x509 PKI Qualified Certificates Profile; EU Directive 1999/93/EC
    # RFC 4158: X509 PKI Certification Path Building
    # RFC 5055: Server-Based Certificate Validation Protocol (SCVP)
    # RFC 2560: Online Certificate Status Protocol (OCSP)
    # RFC 5019: simplified RFC 2560
    # RFC 4387: X509 PKI Operational Protocols: Certificate Store Access via HTTP
    # RFC 5746: TLS Renegotiation Indication Extension http://tools.ietf.org/html/rfc5746,

    # AIA  : {http://www.startssl.com/certs/sub.class4.server.ca.crt}
    # CDP  : {http://www.startssl.com/crt4-crl.crl, http://crl.startssl.com/crt4-crl.crl}
    # OCSP : http://ocsp.startssl.com/sub/class4/server/ca
    # cat some.crl | openssl crl -text -inform der -noout
    # OCSP response "3" (TLS 1.3) ==> certifcate gueltig
    # SPDY - SPDY Protocol : http://www.chromium.org/spdy/spdy-protocol
    # False Start: https://www.imperialviolet.org/2012/04/11/falsestart.html
    #              https://technotes.googlecode.com/git/falsestart.html
    # ALPN : http://tools.ietf.org/html/draft-friedl-tls-applayerprotoneg-02
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
); # %man_text

## definitions: internal functions
## -------------------------------------
sub _man_dbx { print "#" . $ich . "::" . join(" ", @_, "\n") if (grep(/^--v/, @ARGV)>0); }
    # When called from within parent's BEGIN{} section, options are not yet
    # parsed, and so not available in %cfg. Hence we use @ARGV to check for
    # options, which is not performant, but fast enough here.
sub _man_http_head(){
    print "X-Cite: Perl is a mess. But that's okay, because the problem space is also a mess. Larry Wall\r\n";
    print "Content-type: text/plain; charset=utf-8\r\n";
    print "\r\n";
}
sub _man_html_head(){
    print << "EoHTML";
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title> . :  O - S a f t  &#151;  OWASP SSL audit for testers : . </title>
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
}
sub _man_html_foot(){
    print << "EoHTML";
 <a href="https://github.com/OWASP/O-Saft/"   target=_github >Repository</a> &nbsp;
 <a href="https://github.com/OWASP/O-Saft/blob/master/o-saft.tgz" target=_tar ><button value="" />Download (stable)</button></a><br>
 <a href="https://owasp.org/index.php/O-Saft" target=_owasp  >O-Saft Home</a>
 <hr><p><span>&copy; sic[&#x2713;]sec GmbH, 2012 - 2014</span></p>
</body></html>
EoHTML
}

sub _man_html_chck($){
    #? same as _man_html_cbox() but without lable and only if passed parameter start with - or +
    my $n = shift || "";
    return "" if ($n !~ m/^(-|\+)+/);
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
    foreach $n (split(/[\s,]+/,$n)) {
        $a .= sprintf("<a name='a%s'></a>", _man_name_ankor($n));
    }
    return $a;
}
sub _man_html_cbox($) { return sprintf("%8s--%-10s<input type=checkbox name=%-12s value='' >&#160;\n", "", $_[0], '"--' . $_[0] . '"'); }
sub _man_html_text($) { return sprintf("%8s--%-10s<input type=text     name=%-12s size=8 >&#160;\n", "", $_[0], '"--' . $_[0] . '"'); }
sub _man_html_span($) { return sprintf("%8s<span>%s</span><br>\n", "", $_[0]); }
sub _man_html_cmd($)  { return sprintf("%9s+%-10s<input type=text     name=%-12s size=8 >&#160;\n", "", "", '"--' . $_[0] . '"'); }

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
        s/^(=[^ ]+ )//;                             # remove remaining markup
        s/^\s*$/<p>/;                               # add paragraph for formatting
        print;
    }
} # _man_html

sub _man_head($$) { printf("=%14s | %s\n", @_); printf("=%s+%s\n", '-'x15, '-'x60); }
sub _man_opt($$$) { printf("%16s%s%s\n",   @_); }
sub _man_arr($$$) {
    my ($ssl, $sep, $dumm) = @_;
    my @all = ();
    push(@all, sprintf("0x%08X",$_)) foreach (@{$cfg{'cipherranges'}->{$ssl}});
    printf("%16s%s%s\n", $ssl, $sep, join(" ", @all));
}
sub _man_cfg($$$$){
    #? print line in configuration format
    my ($typ, $key, $sep, $txt) = @_;
    $txt =  '"' . $txt . '"' if ($typ =~ m/^cfg/);
    $key =  "--$typ=$key"    if ($typ =~ m/^cfg/);
    _man_opt($key, $sep, $txt);
}

sub _man_usr_value($)   {
    #? return value of argument $_[0] from @{$cfg{'usr-args'}}
    my $key =  shift;
       $key =~ s/^(?:--|\+)//;  # strip leading chars
    my @arg =  "";              # key, value (Note that value is anything right to leftmost = )
    map({@arg = split("=", $_, 2) if /^$key/} @{$cfg{'usr-args'}}); # does not allow multiple $key in 'usr-args'
    return $arg[1];
} # _man_usr_value

## definitions: print functions for help and information
## -------------------------------------

sub man_table($) {
    #? print data from hash in tabular form, $typ denotes hash
    my $typ = shift;
    my %types = (
        # typ        header left    separator  header right
        #-----------+---------------+-------+-------------------------------
        'score' => ["key",           "=",    "SCORE\t# Description"],
        'regex' => ["key",           " => ", " Regular Expressions used internally"],
        'abbr'  => ["Abbrevation",   " - ",  "Description"],
        'intern'=> ["Command",       "    ", " list of commands"],
        'compl' => ["Compliance",    " - ",  "brief description of performed checks"],
        'range' => ["range name",    " - ",  "hex values in this range"],
        'data'  => ["key",    "=",   "text"],
        'check' => ["key",    "=",   "text"],
        'text'  => ["key",    "=",   "text"],
        'cfg_check' =>["N/A", "=",   "N/A"],
        'cfg_data'  =>["N/A", "=",   "N/A"],
        'cfg_text'  =>["N/A", "=",   "N/A"],
    );
    my ($key, $txt);
    my $sep = $types{$typ}->[1];
    _man_dbx("man_table($typ) ...");
    _man_head($types{$typ}->[0], $types{$typ}->[2]) if ($typ !~ m/^cfg/);
    if ($typ eq 'abbr')  { _man_opt(do{(my $a=$_)=~s/ *$//;$a}, $sep, $man_text{'glossar'}->{$_}) foreach (sort keys %{$man_text{'glossar'}}); }
    if ($typ eq 'regex') { _man_opt($_, $sep, $cfg{'regex'}->{$_}) foreach (sort keys %{$cfg{'regex'}}); }
    if ($typ eq 'compl') { _man_opt($_, $sep, $cfg{'compliance'}->{$_}) foreach (sort keys %{$cfg{'compliance'}}); }
    if ($typ eq 'score') { _man_opt($_, $sep .  $checks{$_}->{score}, "\t# " . $checks{$_}->{txt}) foreach (sort keys %checks); }
   #if ($typ eq 'range') { _man_arr($_, $sep, $cfg{'cipherranges'}->{$_}) foreach (sort keys %{$cfg{'cipherranges'}}); }
        # above prints > 65.000 hex values, not very usefull ...
    if ($typ eq 'range') { print qx(\\sed -ne '/^ *.cipherrange. /,/^ *., # cipherranges/p' $0); } # ToDo: quick&dirty backticks
    if ($typ eq 'intern') {
        foreach $key (sort keys %cfg) {
            next if ($key eq 'cmd-intern'); # don't list myself
            next if ($key !~ m/^cmd-(.*)/);
            _man_opt("cmd-" . $1, $sep, "+" . join(" +", @{$cfg{$key}}));
        }
    }
    if ($typ =~ m/check/) {
        foreach $key (sort keys %checks) {
            $txt =  $checks{$key}->{txt};
            _man_cfg($typ, $key, $sep, $txt);
        }
    }
    if ($typ =~ m/data/) {
        foreach $key (sort keys %data) {
            $txt =  $data{$key}->{txt};
            _man_cfg($typ, $key, $sep, $txt);
        }
    }
    if ($typ =~ m/text/) {
        foreach $key (sort keys %text) {
            next if (ref($text{$key}) ne ""); # skip except string
            $txt =  $text{$key};
            $txt =~ s/(\n)/\\n/g;
            $txt =~ s/(\r)/\\r/g;
            $txt =~ s/(\t)/\\t/g;
            _man_cfg($typ, $key, $sep, $txt);
        }
        print "
= Format is:  KEY=TEXT ; NL, CR and TAB are printed as \\n, \\r and \\t
= The string  @@  inside texts is used as placeholder.
= (Don't be confused about multiple  =  as they are part of  TEXT.)
    " if ($typ !~ m/^cfg/);
    }
} # man_table

sub man_commands() {
    #? print commands and short description
    # data is extracted from $parents internal data structure
    my $skip = 1;
    _man_dbx("man_commands($parent) ...");
    # first print general commands, manually crafted here
    # TODO needs to be computed, somehow ...
    print <<EoHelp;
Commands for information about this tool
+dump	Dumps internal data for SSL connection and target certificate.
+exec	Internal command; should not be used directly.
+help	Complete documentation.
+list	Show all ciphers supported by this tool.
+libversion	Show version of openssl.
+quit	Show internal data and exit, used for debugging only.
+VERSION	Just show version and exit.
+version	Show version information for program and Perl modules.
Commands to check SSL details
+bsi	Various checks according BSI TR-02102-2 compliance.
+check	Check the SSL connection for security issues.
+check_sni	Check for Server Name Indication (SNI) usage.
+ev	Various checks according certificate's extended Validation (EV).
+http	Perform HTTP checks.
+info	Overview of most important details of the SSL connection.
+info--v	More detailled overview.
+quick	Quick overview of checks.
+s_client	Dump data retrieved from  "openssl s_client ..."  call.
+sizes	Check length, size and count of some values in the certificate.
+sni	Check for Server Name Indication (SNI) usage.
+sts	Various checks according STS HTTP header.
Commands to test target's ciphers
+cipher	Check target for ciphers (using libssl)
+cipherraw	Check target for all possible ciphers.
EoHelp
    if (open(P, "<", $0)) { # need full path for $parent file here
        while(<P>) {
            # find start of data structure
            # all structure look like:
            #    our %check_some = ( # description
            #          'key' => {... 'txt' => "description of value"},
            #    );
            # where we extract the description of the checked class from first
            # line and the command and its description from the data lines
            if (m/^(?:my|our)\s+%(?:check_(?:[a-z0-9_]+)|data)\s*=\s*\(\s*#\s*(.*)/) {
                $skip = 0;
                print "Commands to show results of checked $1\n"; # print head line, quick&dirty
                next;
            }
            $skip = 1, next if (m/^\s*\)\s*;/); # find end of data structure
            next if ($skip == 1);
            next if (m/^\s*'(?:SSLv2|SSLv3|D?TLSv1|TLSv11|TLSv12|TLSv13)-/); # skip internal counter
            print "+$1\t$2\n" if m/^\s+'([^']*)'.*"([^"]*)"/;
        }
        close(P);
    }
} # man_commands

sub man_html() {
    #? print complete HTML page for o-saft.pl --help=gen-html
    #? recommended usage:   $0 --no-warning --no-header --help=gen-html
    _man_dbx("man_html ...");
    _man_http_head(); #FIXME if (grep(/^usr-cgi/, @{$cfg{'usr-args'}}) > 0);
    _man_html_head();
    _man_html('NAME', 'TODO');
    _man_html_foot();
} # man_html

sub man_cgi() {
    #? print complete HTML page for o-saft.pl used as CGI
    #? recommended usage:   $0 --no-warning --no-header --help=gen-cgi
    #?    o-saft.cgi?--cgi=&--usr&--no-warning&--no-header=&--cmd=html
    _man_dbx("man_cgi ...");
    my $cgi = _man_usr_value('user-action') || _man_usr_value('usr-action') || "/cgi-bin/o-saft.cgi"; # get action from --usr-action= or set to default
#??#    my $cgi = "/cgi-bin/o-saft.cgi"; # get action from --usr-action= or set to default
    my $key = "";
    _man_http_head(); #FIXME if (grep(/^usr-cgi/, @{$cfg{'usr-args'}}) > 0);
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
    foreach $key (qw(cmd cmd cmd cmd)) { print _man_html_cmd($key); }
    print _man_html_br();
    print _man_html_span('check cipher dump check_sni exec help info info--v http quick list libversion sizes s_client version quit sigkey bsi ev cipherraw'); # FIXME: text should be @{$cfg{'cmd-intern'}}
    foreach $key (qw(sslv3 tlsv1 tlsv11 tlsv12 tlsv13 sslv2null BR
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
    foreach $key (qw(separator timeout legacy)) { print _man_html_text($key); }
    print _man_html_br();
    print _man_html_span('cnark sslaudit sslcipher ssldiagnos sslscan ssltest ssltest-g sslyze testsslserver thcsslcheck openssl simple full compact quick'); # FIXME:
    print _man_html_text("format");
    print _man_html_span('csv html json ssv tab xml fullxml raw hex'); # FIXME:
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
} # man_cgi

sub man_wiki() {
    #? print documentation for o-saft.pl in mediawiki format (to be used at owasp.org)
    #? recommended usage:   $0 --no-warning --no-header --help=gen-wiki
    _man_dbx("man_wiki ...");
    my $key = "";
    # 1. generate wiki page header
    print "
==O-Saft==
This is O-Saft's documentation as you get with:
 o-saft.pl --help

__TOC__ <!-- autonumbering is ugly here, but can only be switched of by changing MediaWiki:Common.css -->
<!-- position left is no good as the list is too big and then overlaps some texts
{|align=right
 |<div>__TOC__</div>
 |}
-->

[[Category:OWASP Project]]  [[Category:OWASP_Builders]] [[Category:OWASP_Defenders]]  [[Category:OWASP_Tool]] [[Category:SSL]]
----
";
    # 2.  enerate wiki page content
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
        s/^([^=*].*)/:$1/;              # ident all lines for better readability
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
} # man_wiki

sub man_help($) {
    #? print program's help
    my $label   = lc(shift) || "";      # || to avoid uninitialized value
    my $anf     = uc($label);
    my $end     = "[A-Z]";
    _man_dbx("man_help($anf, $end) ...");
    # no special help, print full one or parts of it
    my $txt = join ("", @DATA);
    if (grep(/^--v/, @ARGV) > 1){       # with --v --v
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
    print $txt;
    if ($label =~ m/^todo/i)    {
        #$\   =  "\n";
        print "\n  NOT YET IMPLEMENTED\n";
        foreach $label (sort keys %checks) {
            next if (_is_member($label, \@{$cfg{'cmd-NOT_YET'}}) <= 0);
            print "  " . $checks{$label}->{txt};
        }
    }
} # man_help

sub printhelp($) {
    #? simple dispatcher for various help requests
    my $hlp = shift;
    _man_dbx("printhelp($hlp) ...");
    # Note: some lower case strings are special
    man_help('NAME'),           return if ($hlp =~ /^$/);
    man_help('TODO'),           return if ($hlp =~ /^todo$/i);
    man_html(),                 return if ($hlp =~ /^(gen-)?html$/);
    man_wiki(),                 return if ($hlp =~ /^(gen-)?wiki$/);
    man_cgi(),                  return if ($hlp =~ /^(gen-)?cgi$/i);
        # Note: gen-cgi is called from within parent's BEGIN and hence
        # causes some   Use of uninitialized value within %cfg 
        # when called as  gen-CGI  it will not be called from within
        # BEGIN amd hence %cfg is defined and will not result in warnings
    # anything below requires data defined in parent
    man_commands(),             return if ($hlp =~ /^commands?$/);
    man_table('abbr'),          return if ($hlp =~ /^(abbr|abk|glossar)$/);
    man_table(lc($1)),          return if ($hlp =~ /^(compl|intern|regex|score|data|check|text|range)(?:iance)?s?$/i);
    man_table('cfg_'.lc($1)),   return if ($hlp =~ /^(check|data|text)s?[_-]?cfg$/i);
    man_table('cfg_'.lc($1)),   return if ($hlp =~ /^cfg[_-]?(check|data|text)s?$/i);
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
        my @txt  = grep(/^=head. (General|Option|--)/, @DATA);  # grep options only
        map({$_ =~ s/^=head. *//} @txt);                        # remove leading markup
        my($end) = grep{$txt[$_] =~ /^Options vs./} 0..$#txt;   # find end of OPTIONS section
        print join("", "OPTIONS\n", splice(@txt, 0, $end));     # print anything before end
        return;
    }
    # nothing matched so far, try to find special section and only print that
    _man_dbx("printhelp: " . uc($hlp));
    man_help(uc($hlp));
    return;
} # printhelp
1;

## documentation
## -------------------------------------
# All documentation is in plain ASCII format.
# Following notations / markups are used:
#   TITEL
#       Titles start at beginning of a line, i.g. all upper case characters
#     SUB-Title
#       Sub-titles start at beginning of a line preceeded by 4 or 6 spaces.
#     code
#       Code lines start at beginning of a line preceeded by 14 spaces.
#   "text in double quotes"
#       References to text or cite
#   'text in single quotes'
#       References to verbatim text elswhere or constant string in description
#   * list item
#     force list item in generated markup
#   ** list item
#     force list item (second level) in generated markup
#   d) list item
#     force list item in generated markup (d may be a digit or character)
#   $VERSION
#     will be replaced by current version string (as defined in caller)
#   $0
#     will be replaced by caller's name (i.g. o-saft.pl)
#
# Initilly the documentation was done using perl's doc format (perldoc, POD).
# The advantage having a well formated output available on various platforms,
# resulted in more difficult efforts extracting information from there.
# In particular following problems occoured:
#   * perldoc is not available on all platforms by default
#   * POD is picky when text lines start with a whitespace
#   * programatically extracting data from POD requires additional substitutes
#   * POD is slow
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

        O-Saft - OWASP SSL audit for testers
                 OWASP SSL advanced forensic tool


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

        * Show details of certificate and connection of target:
          $0 +info example.tld

        * Check certificate, ciphers and SSL connection of target:
          $0 +check example.tld

        * List all available commands:
          $0 --help=commands

        For more specialised test cases, refer to the  COMMANDS  and  OPTIONS
        sections below.

        If no command is given,  +cipher  is used.


WHY?

        Why a new tool for checking SSL security and configuration when there
        are already a dozen or more such tools in existence (circa 2012)?
        Currently available tools suffer from some or all of following issues:
          * lack of tests of unusual ciphers
          * lack of tests of unusual SSL certificate configurations
          * may return different results for the same checks on given target
          * missing tests for modern SSL/TLS functionality
          * missing tests for specific, known SSL/TLS vulnerabilities
          * no support for newer, advanced, features e.g. CRL, OCSP, EV
          * limited capability to create your own customised tests

        Other  reasons or problems  are that they are either binary and hence
        not portable to other (newer) platforms.

        In contrast to (all?) most other tools, including  openssl(1), it can
        be used to "ask simple questions" like "does target support STS" just
        by calling:
          $0 +hsts_sts example.tld

        For more, please see  EXAMPLES  section below.
#
#       or, if written in perl, they mainly use  Net::SSLeay(1)  or 
#       IO::Socket::SSL(1)  which lacks CRL and OCSP and EV checkings.


TECHNICAL INFORMATION

        It is important to understand, which provided information is based on
        data returned by underlaying (used) libraries and the information 
        computed directly.

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

        All checks according the validity of the certificate chain  are based
        on the root CAs installed on the system. NOTE that Net::SSLeay(1) and
        openssl(1)  may have their own rules where to find the root CAs.
        Please refer to the documentation on your system for these tools.
        However, there are folloing options to tweak these rules:
          * --ca-file=FILE
          * --ca-path=DIR
          * --ca-depth=INT

        Above applies to all commands except  +cipherraw  which uses no other
        libraries.


RESULTS

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
              ** all *RC4*  ciphers
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

          All output is designed to be easily parsed by postprocessors.
          Please see  OUTPUT  section below for details.


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

        The summary and internal commands return requested information or the
        results of checks. These are described below.
        The description of all other commands will be printed with:
          $0 --help=commands

    Commands for information about this tool

        All these commands will exit after execution (cannot be used together
        with other commands).

      +ciphers

          Show ciphers offered by local SSL implementation.

          This commands prints the ciphers in a format like "openssl ciphers"
          does. It also accepts the  -v  and  -V  option.
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

          Use  --v  option to show more details.

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

      +sts +hsts

          Various checks according STS HTTP header.
          This option implies  --http,  means that  --no-http is ignored.

      +sni

          Check for Server Name Indication (SNI) usage.

      +sni_check, +check_sni

          Check for Server Name Indication (SNI) usage  and  validity  of all
          names (CN, subjectAltName, FQDN, etc.).

      +bsi

          Various checks according BSI TR-02102-2 compliance.

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
          not checked by default, use  +cipherraw  command for that.

# other names: +cipherall +allciphers +rawciphers
      +cipherraw

          Check target for all possible ciphers.
          Does not depend on local SSL implementation.

          In contrast to  +cipher  this command has some options to tweak the
          cipher tests, connection results and some strange behaviours of the
          target. See  X&Options for  cipherraw  command&  for details.

    Commands to test SSL connection to target

        Please see:
          $0 --help=commands

    Commands to show details of the target's certificate

        Please see:
          $0 --help=commands


OPTIONS

        All options are written in lowercase. Words written in all capital in
        the description here is text provided by the user.

    General options

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

      --help=legacy

          Show possible legacy formats (used as value in  --legacy=TOOL).

      --help=compliance

          Show available compliance checks.

      --help=intern

          Show internal commands.

      --help=range

          Show list of cipherranges (see  --cipherrange=RANGE).

      --help=score

          Show score value for each check.
          Value is printed in format to be used for  --cfg-score=KEY=SCORE.

          Note that the  sequence  of options  is important.  Use the options
          --trace  and/or  --cfg-score=KEY=SCORE  before  --help=score.

      --help=text

          Show texts used in various messages.

      --help=cfg-check

          Show texts used as labels in output for checks (see  +check)  ready
          for use in  RC-FILE  or as option.

      --help=cfg-data

          Show texts used  as labels in output for  data  (see  +info)  ready
          for use in  RC-FILE  or as option.

      --help=cfg-text

          Show texts used in various messages ready for use in  RC-FILE  or
          as option.

      --help=text-cfg

          See --help=cfg-text.

      --help=regex

          Show regular expressions used internally.

      --help=gen-html --help=gen-wiki

          Print documentation in various formats, see o-saft-man.pm.

      --help=gen-cgi

          See o-saft-man.pm.

      --help=glossar

          Show common abbreviation used in the world of security.

      --help=todo

          Show known problems and bugs.

      --no-rc

          Do not read  RC-FILE.

      --dns

          Do DNS lookups to map given hostname to IP, do a reverse lookup.

      --no-dns

          Do not make DNS lookups.
          Note  that the corresponding IP and reverse hostname may be missing
          in some messages then.

      --host=HOST

          Specify  'HOST'  as target to be checked. Legacy option.

      --port=PORT

          Specify  'PORT'  of target to be used. Legacy option.

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

          Make all connection to target using 'PROXYHOST'.

          Also possible is: --proxy=PROXYUSER:PROXYPASS@PROXYHOST:PROXYPORT

      --proxyport=PROXYPORT

          Make all connection to target using 'PROXYHOST:PROXYPORT'.

      --proxyuser=PROXYUSER

          Specify username for proxy authentication.

      --proxypass=PROXYPASS

          Specify password for proxy authentication.

      --starttls

          Use 'STARTTLS' command to start a TLS connection via SMTP.
          This option is a shortcut for  --starttls=SMTP.

      --starttls=PROT

          Use 'STARTTLS' command to start a TLS connection via protocol.
          PROT  may be any of: SMTP, IMAP, IMAP2, POP3, FTPS, LDAP, RDP, XMPP

          For  --starttls=SMTP, see  --dns-mx  also to use MX records instead
          of host

      --starttls-delay=SEC

          Number of seconds to wait before sending a packet, to slow down the
          'STARTTLS' requests. Default is 0.
          This may prevent blocking of requests by the target due to too much
          or too fast connections.
          Note:  In this case there is an automatic suspension and retry with
          a longer delay.

      --cgi, --cgi-exec

          Internal use for CGI mode only.

    Options for SSL tool

      --s_client

          Use  "openssl s_slient ..."  call to retrieve more information from
          the SSL connection.  This is disabled by default on Windows because
          of performance problems. Without this option following informations
          are missing on Windows:
              compression, expansion, renegotiation, resumption,
              selfsigned, verify, chain, protocols
          See  Net::SSLinfo  for details.

          If used together with  --trace, s_client  data will also be printed
          in debug output of  Net::SSLinfo.

      --no-openssl

          Do not use external "openssl"  tool to retrieve information. Use of
          "openssl" is disabled by default on Windows.
          Note that this results in some missing informations.

      --openssl=TOOL

          'TOOL'        can be a path to openssl executable; default: openssl
#         * ssleay:     use installed Net::SSLeay library for perl
#         * x86_32:     use  ** NOT YET IMPLEMENTED **
#         * x86_64:     use  ** NOT YET IMPLEMENTED **
#         * x86Mac:     use  ** NOT YET IMPLEMENTED **
#         * arch:       use  ** NOT YET IMPLEMENTED **

      --force-openssl

          Use openssl to check for supported ciphers;  default: IO::Socket(1)

          This option forces to use  "openssl s_slient -connect CIPHER .." to
          check if a cipher is supported by the remote target. This is useful
          if the  --lib=PATH  option doesn't work (for example due to changes
          of the API or other incompatibilities).

      --exe-path=PATH --exe=PATH

          'PATH'        is a full path where to find openssl.

      --lib-path=PATH --lib=PATH

          'PATH'        is a full path where to find libssl.so and libcrypto.so

          See X&HACKER's INFO& below for a detailed description how it works.

      --envlibvar=NAME

          NAME  is the name of the environment variable containing additional
          paths for searching dynamic shared libraries.
          Default is LD_LIBRARY_PATH.

          Check your system for the proper name, i.e.:
              DYLD_LIBRARY_PATH, LIBPATH, RPATH, SHLIB_PATH.

      --ssl-lazy

          If the  --lib=PATH  option doesn't work (for example due to changes
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
          * info-       are responsible to retrieve information about the SSL
                        connection  and the target certificate (i.g. what the
                        +info  command provides)
          * cipher-     are responsible to connect to the target  and test if
                        it supports the specified ciphers  (i.g. what +cipher
                        command provides)
          * check-      are responsible for performing the checks  (i.e. what
                        is shown with  +check  command)
          * score-      are responsible to compute  the score based on  check
                        results
  
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
          Currently supported are the names and constants of openssl 1.0.1c.
          Example:
            * --cipher=DHE_DSS_WITH_RC4_128_SHA
            * --cipher=0x03000066
            * --cipher=66
          will be mapped to   DHE-DSS-RC4-SHA

          Note: if more than one cipher matches, just one will be selected.

          Default is 'ALL:NULL:eNULL:aNULL:LOW' as specified in Net::SSLinfo.

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

      --SSL, -protocol SSL

      --no-SSL

          * SSL         can be any of:
                        ssl, ssl2, ssl3, sslv2, sslv3, tls1, tls1, tls11,
                        tls1.1, tls1-1, tlsv1, tlsv11, tlsv1.1, tlsv1-1
                        (and similar variants for tlsv1.2).
          For example:  --tls1  --tlsv1  --tlsv1_1  are all the same.

          (--SSL variants):    Test ciphers for this SSL/TLS version.
          (--no-SSL variants): Don't test ciphers for this SSL/TLS version.

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

      --force-sni

          Do not check if SNI seems to be supported by  Net::SSLeay(1).
          Older versions of openssl and its libries do not support SNI or the
          SNI support is implemented buggy. By default it's checked if SNI is
          properly supported. With this option this check can be disabled.

          Be warned that this may result in improper results.

      --sni-name=NAME

          Use  'NAME'  instead of given hostname to connect to  target in SNI
          mode. By  default,  'NAME'  is automatically set to the given FQDN.
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

          Set  'TEXT'  to be returned from  Net::SSLinfo if no certificate data
          is collected due to use of  --no-cert.

      --ca-depth=INT

          Check certificate chain to depth  'INT'  (like openssl's -verify).

      --ca-file=FILE

          Use  'FILE'  with bundle of CAs to verify target's certificate chain.

      --ca-path=DIR

          Use  'DIR'  where to find CA certificates in PEM format.

      --no-nextprotoneg

          Do not use  -nextprotoneg  option for openssl.

      --no-reconnect

          Do not use  -reconnect  option for openssl.

      --no-tlsextdebug

          Do not use  -tlsextdebug  option for openssl.

      --sclient-opt=VALUE

          Argument or option passed to openssl's  s_client  command.

    Options for  cipherraw  command:

      --range=RANGE 
      --cipherrange=RANGE

          Specify range of cipher constants to be tested by  +cipherraw.
          Following 'RANGE's are supported (see also:  --cipherrange=RANGE):
          * rfc                 all ciphers defined in various RFCs
          * shifted             'rfc', shifted by 64 bytes to the right
          * long                like 'rfc' but more lazy list of constants
          * huge                all constants  0x03000000 .. 0x0300FFFF
          * safe                all constants  0x03000000 .. 0x032FFFFF
          * full                all constants  0x03000000 .. 0x03FFFFFF
          * SSLv2               all ciphers according RFC for SSLv2
          * SSLv2_long          more lazy list of constants for SSLv2 ciphers

          Note: 'SSLv2' is the internal list used for testing SSLv2 ciphers.
          It does not make sense to use it for other protocols; however ...

      --ssl-maxciphers=CNT 

          Maximal number of ciphers sent in a sslhello (default: 32).

      --ssl-double-reneg

          Send SSL extension  'reneg_info'  even if list of ciphers includes
          TLS_EMPTY_RENEGOTIATION_INFO_SCSV (default: do not include)

# alias: --sslnodataeqnocipher --nodataeqnocipher
      --ssl-nodata-nocipher

          Do not abort testing for next cipher when the target  responds with
          'NoData' times out. Useful for TLS intolerant servers.
          By default testing for ciphers is aborted  when the target responds
          with 'NoData' message.

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

      --dns-mx, --mx

          Get DNS MX records for given target and check the returned targets.
          (only useful with  --STARTTLS=SMTP)

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
          * sslaudit            format of output similar to  sslaudit
          * sslcipher           format of output similar to  ssl-cipher-check
          * ssldiagnos          format of output similar to  ssldiagnos
          * sslscan             format of output similar to  sslscan
          * ssltest             format of output similar to  ssltest
          * ssltestg            format of output similar to  ssltest -g
          * ssltest-g           format of output similar to  ssltest -g
          * sslyze              format of output similar to  sslyze
          * ssl-cipher-check    same as sslcipher
          * ssl-cert-check      format of output similar to  ssl-cert-check
          * testsslserver       format of output similar to  TestSSLServer.jar
          * thcsslcHeck         format of output similar to  THCSSLCheck

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

      --format=FORM

          'FORM'  may be one of following:

          * 'raw'       Print raw data as passed from  Net::SSLinfo.
            Note:  all data will be printed as is,  without  additional label
            or formatting. It's recommended to use the  option in conjunction
            with exactly one command.  Otherwise the user needs  to know  how
            to "read"  the printed data.

          * 'hex'       Convert some data to hex: 2 bytes separated by ':'.

      --header

          Print formatting header.  Default for  +check,  +info,  +quick  and
          and  +cipher  only.

      --no-header

          Do not print formatting header.
          Usefull if raw output should be passed to other programs.

          Note: must be used on command line to inhibit all header lines.

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

            Tool's Option       (Tool)          $0 Option
          #--------------------+---------------+----------------------------#
          * --capath DIR        (curl)          same as  --ca-path DIR
          * --CApath=DIR        (openssl)       same as  --ca-path DIR
          * --ca-directory=DIR  (wget)          same as  --ca-path DIR
          * --cacert FILE       (curl)          same as  --ca-file DIR
          * --CAfile=FILE       (openssl)       same as  --ca-file DIR
          * --ca-certificate=FILE (wget)        same as  --ca-path DIR
          * -c PATH             (ssldiagnos)    same as  --ca-path DIR
          * --hide_rejected_ciphers (sslyze)    same as  --disabled
          * --http_get          (ssldiagnos)    same as  --http
          * --printcert         (ssldiagnos)    same as  +ciphers
          * --protocol SSL      (ssldiagnos)    same as  --SSL
          * --no-failed         (sslscan)       same as  --disabled
          * --regular           (sslyze)        same as  --http
          * --reneg             (sslyze)        same as  +renegotiation
          * --resum             (sslyze)        same as  +resumtion
          * -h, -h=HOST         (various tools) same as  --host HOST
          * -p, -p=PORT         (various tools) same as  --port PORT
          * -t HOST             (ssldiagnos)    same as  --host HOST
          * --insecure          (cnark.pl)      ignored
          * --nopct --nocolor   (ssldiagnos)    ignored
          * --ism, --pci -x     (ssltest.pl)    ignored
          * --timeout, --grep   (ssltest.pl)    ignored
          * -r,  -s,  -t        (ssltest.pl)    ignored
          * -connect, --fips, -H, -u, -url, -U  ignored
          * -noSSL                              same as  --no-SSL
          * -no_SSL                             same as  --no-SSL

        For definition of  'SSL'  see  --SSL  and  --no-SSL  above.

    Options for customization

          For general descriptions please see  CUSTOMIZATION  section below.

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

      --cfg-checks=KEY=TEXT --cfg-data=KEY=TEXT

          Redefine texts used for labels in output. Sets  %data{KEY}{txt}  or
          %checks{KEY}{txt}  to  TEXT.

          To get a list of preconfigured labels, use:
              $0 --help=cfg-checks
              $0 --help=cfg-data

      --cfg-text=KEY=TEXT

          Redefine general texts used in output. Sets  %text{KEY}  to  TEXT.

          To get a list of preconfigured texts, use:
              $0 --help=cfg-text

          Note that \n, \r and \t are replaced by the corresponding character
          when read from RC-FILE.

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

      --trace-sub, +traceSUB

          Print formatted list of internal functions with their description.
          Not to be intended in conjunction with any target check.

      --trace vs. --v

          While  --v  is used to print more data,  --trace  is used to  print
          more information about internal data such as procedure names and/or
          variable names and program flow.

      --no-warning

          Do not print warning messages (**WARNING:).

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
        used in the RC-FILE, the  --OPTION=VALUE  variant must be used.
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

        All SSL related check performed by the tool will be described here in
        the near future (Any help appreciated ...).

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

        Check if target is vulnerable to Poodle attack.

    SSL Vulnerabilities

      ADH

        Check if ciphers for anonymous key exchange are supported: ADH|DHA.
        Such key exchanges can be sniffed.

      EDH

        Check if ephemeral ciphers are supported: DHE|EDH.
        They are necessary to support Perfect Forward Secrecy (PFS).

      BEAST

        Currently (2014) only a simple check is used: only RC4 ciphers used.
        Which is any cipher with RC4, ARC4 or ARCFOUR.
        TLSv1.2 checks are not yet implemented.

      CRIME

        Connection is vulnerable if target supports SSL-level compression.

      HEARTBLEED

        Check if target is vulnerable to heartbleed attack, see CVE-2014-0160
        and http://heartbleed.com/ .

      Lucky 13

        NOT YET IMPLEMENTED

      RC4

        Check if RC4 ciphers are supported.
        They are assumed to be broken.

      PFS

        Currently (2014) only a simple check is used: only DHE ciphers used.
        Which is any cipher with DHE or ECDHE. SSLv2 does not support PFS.
        TLSv1.2 checks are not yet implemented.

      Poodle

        Check if target is vulnerable to poodle attack (just check if  SSLv3
        is enabled).

    Target (server) Configuration and Support

      BEAST, BREACH, CRIME, Poodle

        See above.

      Renegotiation

        Check if the server allows client-side initiated renegotiation.

      Version rollback attacks

        NOT YET IMPLEMENTED
        Check if the server allows changing the protocol.

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

          * FIPS-140
          * ISM
          * PCI
          * BSI TR-02102

#   NSA Suite B
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

          Only server-side (secure) renegotiation allowed (see RFC5280).

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


SCORING

        Coming soon ...


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
          * --cfg-score=KEY=SCORE
          * --cfg-checks=KEY=TEXT
          * --cfg-data=KEY=TEXT
          * --cfg-text=KEY=TEXT

        Here  'KEY' is the key used in the internal data structure and 'TEXT'
        is the value to be set for this key.  Note that  unknown keys will be
        ignored silently.

        If  'KEY=TEXT'  is an exiting filename,  all lines from that file are
        read and set. For details see  CONFIGURATION FILE  below.

    CONFIGURATION FILE

        Note that the file can contain  'KEY=TEXT'  pairs for the kind of the
        configuration as given by the  --cfg-CFG  option.

        For example  when used with  --cfg-text=file  only values for  %text
        will be set, when used with  --cfg-data=file  only values for  %data
        will be set, and so on.  'KEY'  is not used  when  'KEY=TEXT'  is  an
        existing filename. Though, it's recommended to use a non-existing key,
        for example:  --cfg-text=my_file=some/path/to/private/file .

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
        actually mapped. In particular when  --lib,  --exe  or  --openssl 
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
              EXP-KRB5-RC4-MD5                no

        instead of:
              EXP-KRB5-RC4-MD5                no       weak


    Use of uninitialized value $headers in split ... do_httpx2.al)

        The warning message (like follows or similar):

              Use of uninitialized value $headers in split at blib/lib/Net/SSLeay.pm
              (autosplit into blib/lib/auto/Net/SSLeay/do_httpx2.al) line 1290.

        occurs if the target refused a connection on port 80.
        This is considered a bug in  Net::SSLeay(1).
        Workaround to get rid of this message: use  --no-http  option.

    invalid SSL_version specified at ....

        This error may occur on systems where SSL's DTLSv1 is not supported.
        The full message looks like:
              invalid SSL_version specified at C:/programs/perl/perl/vendor/lib/IO/Socket/SSL.

        Workaround: use  --no-dtlsv1  option.

    Use of uninitialized value $_[0] in length at (eval 4) line 1.

        This warning occours with IO::Socket::SSL 1.967, reason is unknown.
        It seems not to harm functionality, hence no workaround, just ignore.

    Use of uninitialized value in subroutine entry at lib/IO/Socket/SSL.pm line 430.

        Some versions of  IO::Socket::SSL return this error message if  *-MD5
        ciphers are used with other protocols than SSLv2.

        Workaround: use  --no-md5-cipher  option.

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
        +cipher,  +ciphers,  +list,  +libversion,  +version,  +check,  +help.
 
        +quick  should not be used together with other commands, it returns
        strange output then.

        +protocols  requires  openssl(1)  with support for  '-nextprotoneg'
        option. Otherwise the value will be empty.

    Options

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

          This is currently (2014) a limitation in $0.

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
        in the  DEBUG-FILE o-saft-dbx.pm   or  USER-FILE  o-saft-usr.pm  will
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


SEE ALSO

        * openssl(1), Net::SSLeay(1), Net::SSLhello, Net::SSLinfo, timeout(1)
        * http://www.openssl.org/docs/apps/ciphers.html
        * IO::Socket::SSL(1), IO::Socket::INET(1)


HACKER's INFO

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
        openssl subsystem,  influencing both which  executable is called  and
        which shared libraries will be used.

        Why so many options?  Exactly as described above, these options allow
        the users to tune the behaviour of the tool to their needs.  A common
        use case is to enable the use of a separate openssl build independent
        of the openssl package used by the operating system.  This allows the
        user fine grained control over openssl e.g. the encryption suites that
        are compiled/available, without affecting the core system.

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
        tool or lib, a warning like following my occur:

              WARNING: can't open config file: /path/to-openssl/ssl/openssl.cnf

        This warning can be ignored, usually.

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

#       The only code necessary for CGI mode is encapsulated at the beginning,
#       see  'if ($me =~/\.cgi/){ ... }'.  Beside some minor additional regex
#       matches (mainly removing trailing   '=' and empty arguments) no other
#       code is needed. 
#

    Using user specified code

        There are some functions called within the program flow, which can be
        filled with any perl code.  Empty stubs of the functions are prepared
        in  o-saft-usr.pm.  See also  USER-FILE.

    SECURITY

        This tool is designed to be used by people doing security or forensic
        analyses. Hence no malicious input is expected.

        There are no special security checks implemented. Some parameters are
        roughly sanatised according unwanted characters.  In particular there
        are no checks according any kind of code injection.

        Please see  WARNING  above if used in CGI mode. It is not recommended
        to run this tool in CGI mode. You have been warned!

# Program Code below is not shown with +help
#
#    Program Code
#
#        First of all: the main goal is to have a tool to be simple for users.
#        It's not designed to be accademic code or simple for programmers.
#
#      Documentation
#
#        All documentation of code details is  close to the corresponding code
#        lines. Some special comment lines are used, see  X&Comments&  below.
#
#        All documentation for the user is written in  plain ASCII text format
#        at end of this file
#
#        All documentation was initially written in perl's POD format. After 2
#        years of development, it seems that POD wasn't the best decission, as
#        it makes extracting information from documentation complicated, some-
#        times. It's also a huge performance penulty on all platforms.
#
#      General
#
#        Perl's  "die()"  is used whenever an unrecoverable error occurs.  The
#        message printed will always start with '**ERROR: '.
#        warnings are printed using perl's  "warn()"  function and the message
#        always begins with '**WARNING: '.
#
#        All 'print*()' functions write on STDOUT directly.  They are slightly
#        prepared for using texts from  the configuration (%cfg, %checks),  so
#        these texts can be adapted easily (either with  OPTIONS  or in code).
#
#        The  code  mainly uses  'text enclosed in single quotes'  for program
#        internal strings such as hash keys, and uses "double quoted text" for
#        texts being printed. However, exceptions if obviously necessary ;-)
#        strings used for RegEx are always enclosed in single quotes.
#        reason is mainly to make searching texts a bit easyer.
#
#        Calling external programs uses 'qx()' rather than backticks or perl's
#        system()  function. Also not that is uses braces insted of slashes to
#        avoid confusion with RegEx.
#
#        The code flow mainly uses postfix conditions, means the if-conditions
#        are written right of the command to be executed. This is done to make
#        the code better readable (not disturbed by conditions).
#
#        While  Net::SSLinfo  uses  Net::SSLeay(1), o-saft.pl itself uses only
#        IO::Socket::SSL(1). This is done 'cause we need some special features
#        here. However,  IO::Socket::SSL(1)  uses  Net::SSLeay(1)  anyways.
#
#        The code is most likely not thread-safe. Anyway, we don't use them.
#
#        For debugging the code the  --trace  option can be used.  See  DEBUG
#        section below for more details. Be prepared for a lot of output!
#
#      Comments
#
#        Following comments are used in the code:
#
#          # ToDo:       Parts not working perfect, needs to be changed.
#          # FIXME:      Program code known to be buggy, needs to be fixed.
#          #!#           Comments not to be removed in compressed code.
#          #?            Description of sub.
#          ##            Code sections.
#
#      Variables
#
#        Most functions use global variables (even if they are defined in main
#        with 'my'). These variables are mainly: @DATA, @results, %cmd, %data,
#        %cfg, %checks, %ciphers, %text.
#
#        Variables defined with 'our' can be used in   o-saft-dbx.pm   and
#        o-saft-usr.pm.
#
#        For a detailed description of the used variables, please refer to the
#        text starting at the line  '#!# set defaults'.
#
#      Sub Names
#
#        Some rules used for function names:
#
#          check*        Functions which perform some checks.
#          print*        Functions which print results.
#          get_*         Functions to get a value from internal ciphers structure.
#          _<function_name>    Some kind of helper functions.
#          _trace*
#          _y*           Print information when  --trace  is in use.
#          _v*print      Print information when  --v  is in use.
#
#        Function (sub) definitions are followed by a short description, which
#        is just one line right after the 'sub' line. Such lines always start
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
#        Examples to get an overview of workflow:
#          egrep '^##\s' $0
#
#        Following to get perl's variables for checks:
#          $0 +check localhost --trace-key \
#          | awk -F'#' '($2~/^ /){a=$2;gsub(" ","",a);next}(NF>1){printf"%s{%s}\n",a,$2}' \
#          | tr '%' '$'
#
#      Debugging, Tracing
#
#        Most functionality for trace, debug or verbose output is encapsulated
#        in functions (see X&Sub Names& above). These functions are defined as
#        empty stubs herein. The real definitions are in  o-saft-dbx.pm, which
#        is loaded on demand when any  --trace*  or  --v  option is specified.
#        As long as these options are not used  o-saft.pl  works without
#        o-saft-dbx.pm.
#
#        Note: in contrast to the name of the RC-file, the name  o-saft-dbx.pm
#        is hard-coded.


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
                Addition text for verbosity (--v options).

           #[variable name]<TAB>
                Internal variable name (--trace-key options).

           #o-saft.pl::
           #Net::SSLinfo::
                Trace information for --trace  options.

           #{
                Trace information from  NET::SSLinfo  for  --trace  options.
                these are data lines in the format:
                    #{ variable name : value #}
                Note that 'value'  here can span multiple lines and ends with
                    #}


EXAMPLES

        ($0 in all following examples is the name of the tool)

    General

          $0 +cipher some.tld
          $0 +info   some.tld
          $0 +check  some.tld
          $0 +quick  some.tld
          $0 +help=commands
          $0 +list
          $0 +list --v
          $0 +certificate  some.tld
          $0 +fingerprint  some.tld 444
          $0 +after +dates some.tld

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
          $0 +cipherraw some.tld

        * Test using a private libssl.so, libcrypto.so and openssl
          $0 +cipher --lib=/foo/bar-1.42 --exe=/foo/bar-1.42/apps some.tld

        * Test using a private openssl
          $0 +cipher --openssl=/foo/bar-1.42/openssl some.tld

        * Test using a private openssl also for testing supported ciphers
          $0 +cipher --openssl=/foo/bar-1.42/openssl --force-openssl some.tld

        * Show current score settings
          $0 --help=score

        * Change a single score setting
          $0 --cfg-score=http_https=42   +check some.tld

        * Use your private score settings from a file
          $0 --help=score > magic.score
                   edit as needed: magic.score
          $0 --cfg-score    magic.score  +check some.tld

        * Use your private texts in output
          $0 +check some.tld --cfg-text=desc="my special description"

        * Use your private texts from RC-FILE
          $0 --help=cfg-text >> .o-saft.pl
                       edit as needed: .o-saft.pl
          $0 +check some.tld

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
            cnark.pl, SSLAudit.pl sslscan, ssltest.pl, sslyze.py

        O-Saft - OWASP SSL advanced forensic tool
            Thanks to Gregor Kuznik for this title.

        +cipherraw and some proxy functionality implemented by Torsten Gigler.

        For re-writing some docs in proper English, thanks to Robb Watson.

        Code to check heartbleed vulnerability adapted from
            Steffen Ullrich (08. April 2014):
            https://github.com/noxxi/p5-scripts/blob/master/check-ssl-heartbleed.pl


# VERSION string must start with @(#) at beginning of a line
VERSION

        (#) $VERSION

AUTHOR

        31. July 2012 Achim Hoffmann (at) sicsec de

        Project Home: https://www.owasp.org/index.php/O-Saft


# TODO must be last section
TODO

#        nur protokolle testen (wie testssl.sh)
#        openssl (nicht bei 0.9.8, bei 1.0.1*) -legacy_renegotiation
#        Minimal encryption strength:     weak encryption (40-bit) (wie TestSSLServer.jar)
#        "Checking fallback from TLS 1.1 to... TLS 1.0" (wie ssl-cipher-check.pl)
#        SSLCertScanner.exe http://www.xenarmor.com/network-ssl-certificate-scanner.php ansehen
#        ssl-cert-check -p 443 -s mail.google.com -i -V

        * new features
          ** allow proxy
          ** client certificate
          ** some STRATTLS need : HELP STARTTLS HELP as output of HELPs are different
          ** support: PCT protocol

        * missing checks
          ** SSL_honor_cipher_order => 1
          ** implement TLSv1.2 checks
          ** DNSEC and TLSA
          ** IP in CommonName or subjectAltname (RFC6125)
          ** checkcert(): KeyUsage, keyCertSign, BasicConstraints
          ** DV and EV miss some minor checks; see checkdv() and checkev()
          ** some workaround in SSL protocol
          ** +constraints does not check +constraints in the certificate of
             the certificate chain.

        * verify CA chain:
          ** Net::SSLinfo.pm implement verify*
          ** implement +check_chain (see Net::SSLinfo.pm implement verify* also)
          ** implement +ca = +verify +chain +rootcert +expired +fingerprint

        * scoring
          ** implement score for PFS; lower score if not all ciphers support PFS

        * vulnerabilities
          ** complete TIME, BREACH check
          ** implement check for Lucky 13
          ** is DHE-DSS-RC4-SHA also weak?
          ** BEAST more checks, see: http://www.bolet.org/TestSSLServer/

        * Net::SSLeay
          ** Net::SSLinfo.pm Net::SSLeay::ctrl()  sometimes fails, but doesn't
             return error message
          ** Net::SSLeay::CTX_clear_options()
             Need to check the difference between the  SSL_OP_LEGACY_SERVER_CONNECT  and
             SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION;  see also SSL_clear_options().
             see https://www.openssl.org/docs/ssl/SSL_CTX_set_options.html

        * Windows
          ** Unicode:
             try: cmd /K chcp 65001
             or:  chcp 65001
             or:  reg add hklm\system\currentcontrolset\control\nls\codepage -v oemcp -d 65001

        * internal
          ** make a clear concept how to handle +CMD whether they report
             checks or informations (aka %data vs. %check_*)
             currently (2014) each single command returns all values
          ** complete +http checks (see %checks also)
             improve score for these checks
             make clear usage of score from %checks
          ** client certificates not yet implemented in _usesocket() _useopenssl(),
             see t.client-cert.txt
          ** (nicht wichtig, aber sauber programmieren)
             _get_default(): Net::SSLinfo::default() benutzen

END # mandatory to keep some grep happy
