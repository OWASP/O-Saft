#!/usr/bin/perl
## PACKAGE {

#!# Copyright (c) Achim Hoffmann, sic[!]sec GmbH
#!# This  software is licensed under GPLv2. Please see o-saft.pl for details.

## no critic qw(Documentation::RequirePodSections)
#  our POD below is fine, perlcritic (severity 2) is too pedantic here.

package OSaft::Doc::Glossary;

use strict;
use warnings;

my  $VERSION    = "17.10.17";  # official verion number of tis file
my  $SID        = "@(#) Glossary.pm 1.6 18/01/13 21:56:44";

print STDERR "**WARNING: OSaft::Doc::Glossary obsolete since O-Saft version 18.01.18";

#_____________________________________________________________________________
#_____________________________________________________ public documentation __|

=pod

=encoding utf8

=head1 NAME

OSaft::Doc::Glossary - common perl module to define O-Saft glossary texts

=head1 SYNOPSIS

    use OSaft::Doc::Glossary;

=head1 METHODS

=head2 get()

Return all data.

=cut

#_____________________________________________________________________________
#__________________________________________________________________ methods __|

sub get           { return <DATA>; }
sub print_as_text { print  <DATA>; return; }
sub o_saft_glossary_done() {};  # dummy to check successful include

## PACKAGE }

#_____________________________________________________________________________
#_____________________________________________________________________ self __|

print_as_text() if (! defined caller);
1;

# All documentation following  __DATA__  is in plain ASCII format.
# It's designed for human radability and simple editing.
# Syntax is:
#       each line consist of a KEY and a TEXT
#       KEY and a TEXT are separated by TAB (aka \09 aka 0x09)
# To support duplicate keys, for example because they have different TEXTs,
# some keys may hav added whitespaces on right.
# Keys which contain spaces at right siteto make key unique:  CBC, CSP, EME

__DATA__

AA	Attribute Authority
AAD	additional authenticated data
ACME	Automated Certificate Management Environment
ACL	Access Control List
ADH	Anonymous Diffie-Hellman
Adler32	hash function
AE	Authenticated Encryption
AEAD	Authenticated Encryption with Additional Data
AECDHE	Anonymous Ephemeral ECDH
AEM	Authenticated Encryption Mode aka Advanced Encryption Mode aka OCB3
AES	Advanced Encryption Standard
AES-XTS	?
AIA	Authority Information Access (certificate extension)
AKC	Agreement with Key Confirmation
AKID	Authority Key IDentifier
ALPN	Application Layer Protocol Negotiation
ARC4	Alleged RC4 (see RC4)
ARCFOUR	alias for ARC4
ARIA	128-bit Symmetric Block Cipher
ASN	Autonomous System Number
ASN.1	Abstract Syntax Notation number One
BACPA	Blockwise-adaptive chosen-plaintext attack
bcrypt	hash function (Niels Provos, David Mazières, 1999)
BLAKE	hash function (Jean-Philippe Aumasson, Luca Henzen, Willi Meier, Raphael C.-W. Phan, 2008)
BLAKE2	fast secure hashing function (2012)
BLAKE-224	see BLAKE (224 bit)
BLAKE-256	see BLAKE (256 bit)
BLAKE-384	see BLAKE (384 bit)
BLAKE-512	see BLAKE (512 bit)
BEAR	block cipher combining stream cipher and hash function
BDH	Bilinear Diffie-Hellman
BEAST	Browser Exploit Against SSL/TLS
BER	Basic Encoding Rules
BGP	Boorder Gateway Protocol
Blowfish	symmetric block cipher
boomerang attack	attack on BLAKE
Brainpool	signature algorithm, from BSI
BREACH	Browser Reconnaissance & Exfiltration via Adaptive Compression of Hypertext (a variant of CRIME)
Bullrun	NSA program to break encrypted communication
CAMELLIA	Encryption algorithm 128 bit (by Mitsubishi and NTT)
CAST-128	Carlisle Adams and Stafford Tavares, block cipher
CAST5	alias for CAST-128
CAST-256	Carlisle Adams and Stafford Tavares, block cipher
CAST6	alias for CAST-256
cipher suite	cipher suite is a named combination of authentication, encryption, and message authentication code algorithms
CA	Certificate Authority (aka root CA)
CAA	Certificate Authority Authorization
CAA RR	CAA Resource Record
CBC	Cyclic Block Chaining
CBC 	Cipher Block Chaining (sometimes)
CBC  	Ciplier Block Chaining (sometimes)
CBC-MAC	Cipher Block Chaining - Message Authentication Code
CBC-MAC-ELB	Cipher Block Chaining - Message Authentication Code - Encrypt Last Block
CCM	CBC-MAC Mode
CCS	Change Cipher Spec (protocol)
CDH	?  Diffie-Hellman
CDP	CRL Distribution Points
CEK	Content Encryption Key
CFB	Cipher Feedback
CFB3	Cipher Feedback
CFBx	Cipher Feedback x bit mode
ChaCha	stream cipher algorithm
ChaCha-Poly1305	Authenticated Encryption with Associated Data (AEAD)
CHAP	Challenge Handshake Authentication Protocol
CKA	(PKCS#11)
CKK	(PKCS#11)
CKM	(PKCS#11)
CMAC	Cipher-based MAC
CMC	CBC-mask-CBC
CMP	X509 Certificate Management Protocol
CMS	Cryptographic Message Syntax
CMVP	Cryptographic Module Validation Program (NIST)
CN	Common Name
CP	Certificate Policy (certificate extension)
CPD	Certificate Policy Definitions
CPS	Certification Practice Statement
CRC	Cyclic Redundancy Check
CRC8	CRC with polynomial length 8
CRC16	CRC with polynomial length 16
CRC32	CRC with polynomial length 32
CRC64	CRC with polynomial length 64
CRAM	Challenge Response Authentication Mechanism
CRIME	Compression Ratio Info-leak Made Easy (Exploit SSL/TLS)
CRL	Certificate Revocation List
CSP	Certificate Service Provider
CSP 	Cryptographic Service Provider
CSP  	Critical Security Parameter (used in FIPS 140-2)
CSP:	Content Security Policy (used as HTTP header)
CSR	Certificate Signing Request
CT	Certificate Transparency
CTL	Certificate Trust Line
CTR	Counter Mode (sometimes: CM; block cipher mode)
CTS	Cipher Text Stealing
Curve448	signature algorithm, aka Goldilocks (224 bit)
Curve25519	signature algorithm by Dan J. Bernstein (ca. 128 bit)
CWC	CWC Mode (Carter-Wegman + CTR mode; block cipher mode)
DAA	Data Authentication Algorithm
DAC	Data Authentication Code
DACL	Discretionary Access Control List
DANE	DNS-based Authentication of Named Entities
DDH	Decisional Diffie-Hellman (Problem)
DEA	Data Encryption Algorithm (sometimes a synonym for DES)
DECIPHER	synonym for decryption
DEK	Data Encryption Key
DER	Distinguished Encoding Rules
DES	Data Encryption Standard
DESede	alias for 3DES ?java only?
DESX	extended DES
3DES	Tripple DES (168 bit)
3DES-EDE	alias for 3DES
3TDEA	Three-key  Tripple DEA (sometimes: Tripple DES; 168 bit)
2TDEA	Double-key Tripple DEA (sometimes: Double DES; 112 bit)
D5	Verhoeff's Dihedral Group D5 Check
DH	Diffie-Hellman
DHE	Diffie-Hellman ephemeral (historic acronym, often used, mainly in openssl)
DLIES	Discrete Logarithm Integrated Encryption Scheme
DLP	Discrete Logarithm Problem
DN	Distinguished Name
DNSSEC	DNS Security Extension
DPA	Dynamic Passcode Authentication (see CAP)
DRBG	Deterministic Random Bit Generator
DROWN	Decrypting RSA with Obsolete and Weakened eNcryption (Exploit SSL/TLS)
DSA	Digital Signature Algorithm
DSS	Digital Signature Standard
DTLS	Datagram TLS
DTLSv1	Datagram TLS 1.0
Dual EC DBRG	Dual Elliptic Curve Deterministic Random Bit Generator
DV	Domain Validation
DV-SSL	Domain Validated Certificate
EAL	Evaluation Assurance Level
EAP	Extensible Authentication Protocol
EAP-PSK	Extensible Authentication Protocol using a Pre-Shared Key
EAX	EAX Mode (block cipher mode)
EAXprime	alias for EAX Mode
EBC	Edge Boundery Controller
EC	Elliptic Curve
ECB	Electronic Code Book mode
ECC	Elliptic Curve Cryptography
ECDH	Elliptic Curve Diffie-Hellman
ECDHE	Ephemeral ECDH
ECDSA	Elliptic Curve Digital Signature Algorithm
ECGDSA	Elliptic Curve ??? DSA
ECHO	hash function (Ryad Benadjila, Olivier Billet, Henri Gilbert, Gilles Macario-Rat, Thomas Peyrin, Matt Robshaw, Yannick Seurin, 2010)
ECIES	Elliptic Curve Integrated Encryption Scheme
ECKA	Elliptic Curve Key Agreement
ECKA-EG	Elliptic Curve Key Agreement of ElGamal Type
ECKDSA	Elliptic Curve ??? DSA
ECMQV	Elliptic Curve Menezes-Qu-Vanstone
ECOH	Elliptic Curve only hash
#       'ECRYPT	 ?? 
Ed25519	alias for Curve25519
Ed448	alias for Curve448
EDE	Encryption-Decryption-Encryption
EDH	Ephemeral Diffie-Hellman
EGADS	Entropy Gathering and Distribution System
EGD	Entropy Gathering Daemon
EKU	Extended Key Usage
ELB	Encrypt Last Block
ElGamal	asymmetric block cipher
ENCIPHER	synonym for encryption
EME	ECB-mask-ECB
EME 	Encoding Method for Encryption
ESP	Encapsulating Security Payload
ESSIV	Encrypted salt-sector initialization vector
EtM	Encrypt-then-MAC
ETSI-TS	European Telecommunications Standards Institute - Technical Specification
EV	Extended Validation
EV-SSL	Extended Validation Certificate
FEAL	Fast Data Encryption Algorithm
FFC	Finite Field Cryptography
FFT	Fast Fourier Transform
FIPS	Federal Information Processing Standard
FIPS46-2	FIPS Data Encryption Standard (DES)
FIPS73	FIPS Guidelines for Security of Computer Applications
FIPS140-2	FIPS Security Requirements for Cryptographic Modules
FIPS140-3	proposed revision of FIPS 140-2
FIPS180-3	FIPS Secure Hash Standard
FIPS186-3	FIPS Digital Signature Standard (DSS)
FIPS197	FIPS Advanced Encryption Standard (AES)
FIPS198-1	FIPS The Keyed-Hash Message Authentication Code (HMAC)
FREAK	Factoring Attack on RSA-EXPORT Keys
FQDN	Fully-qualified Domain Name
FSB	Fast Syndrome Based Hash
FSM	Finite State Machine
FZA	FORTEZZA
G-DES	??? DES
GCM	Galois/Counter Mode (block cipher mode)
GHASH	Hash funtion used in GCM
GMAC	MAC for GCM
Grøstl	hash function (Lars Knudsen, 2010)
Goldilocks	see Curve448
GOST	Gossudarstwenny Standard (block cipher)
Grainv1	stream cipher (64-bit IV)
Grainv128	stream cipher (96-bit IV)
GREASE	Generate Random Extensions And Sustain Extensibility
HAIFA	HAsh Iterative FrAmework
hash127	fast hash function (by Dan Bernstein)
HAVAL	one-way hashing
HAS-160	hash function
HAS-V	hash function
HC128	stream cipher
HC256	stream cipher
HEARTBLEED	attack against TLS extension heartbeat
HEIST	HTTP Encrypted Information can be Stolen through TCP-windows
HIBE	hierarchical identity-based encryption
HNF-256	hash function (Harshvardhan Tiwari, Krishna Asawa, 2014)
HMAC	keyed-Hash Message Authentication Code
HMQV	h? Menezes-Qu-Vanstone
HSM	Hardware Security Module
HPKP	HTTP Public Key Pinning
HSR	Header + Secret + Random
HSTS	HTTP Strict Transport Security
HTOP	HMAC-Based One-Time Password
IAPM	Integrity Aware Parallelizable Mode (block cipher mode of operation)
ICM	Integer Counter Mode (alias for CTR)
IDP	Issuing Distribution Points
IDEA	International Data Encryption Algorithm (by James Massey and Xuejia Lai)
IESG	Internet Engineering Steering Group
IETF	Internet Engineering Task Force
IFC	Integer Factorization Cryptography
IGE	Infinite Garble Extension
IKE	Internet Key Exchange
IKEv2	IKE version 2
IND-BACPA	Indistinguishability of encryptions under blockwise-adaptive chosen-plaintext attack
IND-CCA	Indistinguishability of encryptions under chosen-cipgertext attack
IND-CPA	Indistinguishability of encryptions under chosen-plaintext attack
INT-CTXT	Integrity of ciphertext
INT-PTXT	Integrity of plaintext
ISAKMP	Internet Security Association and Key Management Protocol
IV	Initialization Vector
JH	hash function (Hongjun Wu, 2011)
JSSE	Java Secure Socket Extension
Keccak	hash function (Guido Bertoni, Joan Daemen, Michaël Peeters und Gilles Van Assche, 2012)
KCI	Key Compromise Impersonation
KEA	Key Exchange Algorithm (alias for FORTEZZA-KEA)
KEK	Key Encryption Key
KSK	Key Signing Key (DNSSEC)
KU	Key Usage
LAKE	hash function (Jean-Philippe Aumasson, Willi Meier, Raphael C.-W. Phan, 2008)
LFSR	Linear Feedback Shift Register
LION	block cipher combining stream cipher and hash function
LLL	Lenstra–Lenstra–Lovász, lattice basis reduction algorithm
LM hash	LAN Manager hash aka LanMan hash
Logjam	Attack to force server to downgrade to export ciphers
LRA	Local Registration Authority
LRW	Liskov, Rivest, and Wagner (blok encryption)
Lucky 13	Break SSL/TLS Protocol
MARS	
MAC	Message Authentication Code
MCF	Modular Crypt Format
MDC2	Modification Detection Code 2 aka Meyer-Schilling
MDC-2	same as MDC2
MD2	Message Digest 2
MD4	Message Digest 4
MD5	Message Digest 5
MEE	MAC-then-Encode-then-Encrypt
MEK	Message Encryption Key
MECAI	Mutually Endorsing CA Infrastrukture
MGF	Mask Generation Function
MISTY1	block cipher algorithm
MQV	Menezes-Qu-Vanstone (authentecated key agreement
MtE	MAC-then-encrypt
NCP	Normalized Certification Policy (according TS 102 042)
Neokeon	symmetric block cipher algorithm
nonce	(arbitrary) number used only once
NPN	Next Protocol Negotiation
NSS	Network Security Services
NTLM	NT Lan Manager. Microsoft Windows challenge-response authentication method.
NULL	no encryption
NUMS	nothing up my sleeve numbers
OAEP	Optimal Asymmetric Encryption Padding
OCB	Offset Codebook Mode (block cipher mode of operation)
OCB1	same as OCB
OCB2	improved OCB aka AEM
OCB3	improved OCB2
OCSP	Online Certificate Status Protocol
OCSP stapling	formerly known as: TLS Certificate Status Request
OFB	Output Feedback
OFBx	Output Feedback x bit mode
OID	Object Identifier
OMAC	One-Key CMAC, aka CBC-MAC
OMAC1	same as CMAC
OMAC2	same as OMAC
OPIE	One-time pad Password system
OTP	One Time Pad
OV	Organisational Validation
OV-SSL	Organisational Validated Certificate
P12	see PKCS#12
P7B	see PKCS#7
PACE	Password Authenticated Connection Establishment
PAKE	Password Authenticated Key Exchange
PBE	Password Based Encryption
PBKDF2	Password Based Key Derivation Function
PC	Policy Constraints (certificate extension)
PCBC	Propagating Cipher Block Chaining
PCFB	Periodic Cipher Feedback Mode
PCT	Private Communications Transport
PEM	Privacy Enhanced Mail
PES	Proposed Encryption Standard
PFS	Perfect Forward Secrecy
PFX	see PKCS#12 (Personal Information Exchange)
PGP	Pretty Good Privacy
PII	Personally Identifiable Information
PKCS	Public Key Cryptography Standards
PKCS1	PKCS #1: RSA Encryption Standard
PKCS3	PKCS #3: RSA Encryption Standard on how to implement the Diffie-Hellman key exchange protocol
PKCS5	PKCS #5: RSA Encryption Standard on how to derive cryptographic keys from a password
PKCS6	PKCS #6: RSA Extended Certificate Syntax Standard
PKCS7	PKCS #7: RSA Cryptographic Message Syntax Standard
PKCS8	PKCS #8: RSA Private-Key Information Syntax Standard
PKCS10	PKCS #10: Describes a standard syntax for certification requests
PKCS11	PKCS #11: RSA Cryptographic Token Interface Standard (keys in hardware devices, cards)
PKCS12	PKCS #12: RSA Personal Information Exchange Syntax Standard (public + private key stored in files)
PKE	Public Key Enablement
PKI	Public Key Infrastructure
PKIX	Internet Public Key Infrastructure Using X.509
PKP	Public-Key-Pins
PM	Policy Mappings (certificate extension)
PMAC	Parallelizable MAC (by Phillip Rogaway)
PMS	pre-master secret
Poly1305	Authenticator
Poly1305-AES	MAC (by D. Bernstein)
POP	Proof of Possession
POODLE	Padding Oracle On Downgraded Legacy Encryption
PRF	pseudo-random function
PRNG	pseudo-random number generator
PSK	Pre-shared Key
PWKE	Pair-Wise Key Establishment Schemes Using Discrete Logarithm Cryptography
QUIC	Quick UDP Internet Connection
RA	Registration Authority (aka Registration CA)
Rabbit	stream cipher algorithm
RADIUS	Remote Authentication Dial-In User Service
Radix-64	alias for Base-64
RBG	Random Bit Generator
RC2	Rivest Cipher 2, block cipher by Ron Rivest (64-bit blocks)
RC4	Rivest Cipher 4, stream cipher (aka Ron's Code)
RC5	Rivest Cipher 5, block cipher (32-bit word)
RC5-64	Rivest Cipher 5, block cipher (64-bit word)
RC6	Rivest Cipher 6
RCSU	Reuters' Compression Scheme for Unicode (aka SCSU)
RFC	Request for Comments
Rijndael	symmetric block cipher algorithm
RIPEMD	RACE Integrity Primitives Evaluation Message Digest
RMAC	Randomized MAC (block cipher authentication mode)
RNG	Random Number Generator
ROT-13	see XOR
ROBOT	Return Of Bleichenbacher's Oracle Threat
RTP	Real-time Transport Protocol
RSA	Rivest Sharmir Adelman (public key cryptographic algorithm)
RSS-14	Reduced Space Symbology, see GS1
RTN	Routing transit number
S/KEY	One-time pad Password system
SA	Subordinate Authority (aka Subordinate CA)
SACL	System Access Control List
SAFER	Secure And Fast Encryption Routine, block cipher
Salsa20	stream cipher (by D. Bernstein, 2005)
Salsa20/8	see scrypt
Salsa20/12	see Salsa20
Salsa20/20	see Salsa20
SAM	syriac abbreviation mark
SAN	Subject Alternate Name
Sarmal	hash function
SAX	Symmetric Authenticated eXchange
SCA	Selfsigned CA signature
SBCS	single-byte character set
SCEP	Simple Certificate Enrollment Protocol
scrypt	password based key derivation function (Colin Percival)
SCSU	Standard Compression Scheme for Unicode (compressed UTF-16)
SCSV	Signaling Cipher Suite Value
SCVP	Server-Based Certificate Validation Protocol
SCT	Signed Certificate Timestamp
SDES	Security Description Protokol
SEED	128-bit Symmetric Block Cipher
Serpent	symmetric key block cipher (128 bit)
SGC	Server-Gated Cryptography
SGCM	Sophie Germain Counter Mode (block cipher mode)
SHA	Secure Hash Algorithm
SHA-0	Secure Hash Algorithm (insecure version before 1995)
SHA-1	Secure Hash Algorithm (since 1995)
SHA-2	Secure Hash Algorithm (since 2002)
SHA-3	Secure Hash Algorithm (since 2015), see Keccak also
SHA-224	Secure Hash Algorithm (224 bit)
SHA-256	Secure Hash Algorithm (256 bit)
SHA-384	Secure Hash Algorithm (384 bit)
SHA-512	Secure Hash Algorithm (512 bit)
SHA1	see for SHA-1 (160 bit)
SHA2	see for SHA-2 (224, 256, 384 or 512 bit)
SHA3	see for SHA-3 (224, 256, 384 or 512 bit)
SHA3-224	Secure Hash Algorithm (224 bit)
SHA3-256	Secure Hash Algorithm (256 bit)
SHA3-384	Secure Hash Algorithm (384 bit)
SHA3-512	Secure Hash Algorithm (512 bit)
SHAKE128	Secure Hash Algorithm (variable bit)
SHAKE256	Secure Hash Algorithm (variable bit)
SHAvite-3	hash function (Eli Biham, Orr Dunkelman, 2009)
SPHINCS	post-quantum hash function
SPHINCS-256	alias for SPHINCS
SWIFFT	hash function (Vadim Lyubashevsky, Daniele Micciancio, Chris Peikert, Alon Rosen, 2008)
SWIFFTX	see SWIFFT
SHS	Secure Hash Standard
SIA	Subject Information Access (certificate extension)
SIC	Segmented Integer Counter (alias for CTR)
Skein	hash function (Niels Ferguson, Stefan Lucks, Bruce Schneier, Doug Whiting, Mihir Bellare, Tadayoshi Kohno, Jon Callas, Jesse Walker, 2010)
SKID	subject key ID (certificate extension)
SKIP	Message Skipping Attacks on TLS
SKIP-TLS	see SKIP
Skipjack	block cipher encryption algorithm specified as part of the Fortezza
SLOTH	Security Losses from Obsolete and Truncated Transcript Hashes
SMACK	State Machine AttaCKs
Snefu	hash function
SNI	Server Name Indication
SNOW	word-based synchronous stream ciphers (by Thomas Johansson and Patrik Ekdahl )
Snuffle 2005	see Salsa20
Snuffle 2008	see ChaCha
SPDY	Google's application-layer protocol on top of SSL
SPKI	Subject Public Key Infrastructure
SPN	Substitution-Permutation Network
Square	block cipher
SRI	Subresource Integrity
SRP	Secure Remote Password protocol
SRTP	Secure RTP
SSCD	Secure Signature Creation Device
SSEE	Sichere Signaturerstellungseinheit (same as SSCD)
SSL	Secure Sockets Layer
SSLv2	Secure Sockets Layer Version 2
SSLv3	Secure Sockets Layer Version 3
SSP	Security Support Provider
SSPI	Security Support Provider Interface
SST	Serialized Certificate Store format
SCT	Signed Certificate Timestamp
STS	Strict Transport Security
STS 	Station-to-Station protocol
Sweet32	Sweet32: Birthday attacks on 64-bit block ciphers in TLS and OpenVPN
TA	Trust Agent
TACK	Trust Assertions for Certificate Keys
TCB	Trusted Computing Base
TDEA	Tripple DEA
TEA	Tiny Encryption Algorithm
TEK	Traffic Encryption Key
Tiger	hash function
TIME	Timing Info-leak Made Easy (Exploit SSL/TLS)
TIME 	A Perfect CRIME? TIME Will Tell
Threefish	hash function
TLS	Transport Layer Security
TLSA	TLS Trust Anchors
TLSv1	Transport Layer Security version 1
TLSA RR	TLSA resource Record
TMAC	Two-Key CMAC, variant of CBC-MAC
TOCTOU	Time-of-check, time-of-use
TOFU	Trust on First Use
TR-02102	Technische Richtlinie 02102 (des BSI)
TR-03116	Technische Richtlinie 03116 (des BSI)
TSK	Transmission Security Key
TSK 	TACK signing key
TSP	trust-Management Service Provider
TSS	Time Stamp Service
TTP	trusted Third Party
Twofish	symmetric key block cipher (128 bit)
UC 	Unified Capabilities
UC	Unified Communications (SSL Certificate using SAN)
UCC	Unified Communications Certificate (rarley used)
UMAC	Universal hashing MAC; optimized for 32-bit architectures
URI	Uniform Resource Identifier
URL	Uniform Resource Locator
VMAC	Universal hashing MAC; 64-bit variant of UMAC (by Ted Krovetz and Wei Dai)
VMPC	stream cipher
WHIRLPOOL	hash function
X.680	X.680: ASN.1
X.509	X.509: The Directory - Authentication Framework
X25519	alias for Curve25519 ?
X680	X.680: ASN.1
X509	X.509: The Directory - Authentication Framework
XCBC	eXtended CBC-MAC
XCBC-MAC	same as XCBC
XEX	XOR Encrypt XOR
XKMS	XML Key Management Specification
XMACC	counter-based XOR-MAC
XMACR	radomized XOR-MAC
XMLSIG	XML-Signature Syntax and Processing
XMSS	hash function
XSalsa2	variant of Salsa20
XTEA	extended Tiny Encryption Algorithm
XTS	XEX-based tweaked-codebook mode with ciphertext stealing
XUDA	Xcert Universal Database API
XXTEA	enhanced/corrected Tiny Encryption Algorithm
ZLIB	Lossless compression file format
ZRTP	SRTP for VoIP
ZSK	Zone Signing Key (DNSSEC)

