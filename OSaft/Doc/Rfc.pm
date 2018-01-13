#!/usr/bin/perl
## PACKAGE {

#!# Copyright (c) Achim Hoffmann, sic[!]sec GmbH
#!# This  software is licensed under GPLv2. Please see o-saft.pl for details.

## no critic qw(Documentation::RequirePodSections)
#  our POD below is fine, perlcritic (severity 2) is too pedantic here.

package OSaft::Doc::Rfc;

use strict;
use warnings;

my  $VERSION    = "17.10.17";  # official verion number of tis file
my  $SID        = "@(#) Rfc.pm 1.6 18/01/13 21:53:23";

print STDERR "**WARNING: OSaft::Doc::Rfc obsolete since O-Saft version 18.01.18";

#_____________________________________________________________________________
#_____________________________________________________ public documentation __|

=pod

=encoding utf8

=head1 NAME

OSaft::Doc::Rfc - common perl module to define RFC (number and title) related
to SSL/TLS.

=head1 SYNOPSIS

    use OSaft::Doc::Rfc;

=head1 METHODS

=head2 get()

Return all data.

=cut

#_____________________________________________________________________________
#__________________________________________________________________ methods __|

sub get           { return <DATA>; }
sub print_as_text { print  <DATA>; return; }
sub o_saft_rfc_done() {};       # dummy to check successful include

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
# First line contains base URL to find RFC.

# number   | title / description
#----------+----------------------------------------+-----------------------+
    # zu RFC 2412:
    #           alle *DH* sind im Prinzip PFS.
    #           wird manchmal zusaetzlich mit DHE bezeichnet, wobei E für ephemeral
    #           also flüchtige, vergängliche Schlüssel steht
    #           D.H. ECDHE_* und DHE_* an den Anfang der Cipherliste stellen, z.B.
    #                TLS_ECDHE_RSA_WITH_RC4_128_SHA
    #                TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    #                TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    #                TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA 
    # zu RFC 4366
                   # AKID - authority key identifier
                   # Server name Indication (SNI): server_name
                   # Maximum Fragment Length Negotiation: max_fragment_length
                   # Client Certificate URLs: client_certificate_url
                   # Trusted CA Indication: trusted_ca_keys
                   # Truncated HMAC: truncated_hmac
                   # Certificate Status Request (i.e. OCSP stapling): status_request
                   # Error Alerts
    # zu RFC 6066
                   # PkiPath
                   # Truncated CA keys (value 3)
                   # Truncated HMAC (value 4)
                   # (Certificate) Status Request (value 5)
                   # OCSP stapling mechanism
    # zu RFC 6125
                   # Representation and Verification of Domain-Based Application Service
                   # Identity within Internet Public Key Infrastructure Using X.509 (PKIX)
                   # Certificates in the Context of Transport Layer Security (TLS)

__DATA__

# url	base URL for RFC descriptions
#	http://tools.ietf.org/html/rfcXXXX
#	http://tools.ietf.org/rfc/rfcXXXX.txt
url	http://tools.ietf.org/
6167	Prohibiting Secure Sockets Layer (SSL) Version 2.0
6101	SSL Version 3.0
2246	TLS Version 1.0 (with Cipher Suites)
4346	TLS Version 1.1 (with Cipher Suites)
5246	TLS Version 1.2 (with Cipher Suites)
4347	DTLS Version 0.9
6347	DTLS Version 1.2
2616	Hypertext Transfer Protocol Version 1 (HTTP/1.1)
7540	Hypertext Transfer Protocol Version 2 (HTTP/2)
7230	HTTP/1.1: Message Syntax and Routing
7231	HTTP/1.1: Semantics and Content
7232	HTTP/1.1: Conditional Requests
7233	HTTP/1.1: Range Requests
7234	HTTP/1.1: Caching
7235	HTTP/1.1: Authentication
3490	Internationalizing Domain Names in Applications (IDNA)
3987	Internationalized Resource Identifiers (IRIs)
4518	Internationalized String Preparation in LDAP
3986	Uniform Resource Identifier (URI): Generic Syntax
2104	HMAC: Keyed-Hashing for Message Authentication
2405	The ESP DES-CBC Cipher Algorithm With Explicit IV
2406	IP Encapsulating Security Payload (ESP)
2407	The Internet IP Security Domain of Interpretation for ISAKMP
2408	Internet Security Association and Key Management Protocol (ISAKMP)
2409	The Internet Key Exchange (IKE) - 1998
4306	The Internet Key Exchange (IKEv2) Protocol - 2005
7296	The Internet Key Exchange Protocol 2 (IKEv2) - 2014
4753	ECP Groups for IKE and IKEv2
2412	AKLEY Key Determination Protocol (PFS - Perfect Forward Secrec)
2818	HTTP Over TLS
2945	SRP Authentication & Key Exchange System
2986	PKCS#10
5967	PKCS#10
5081	TLSPGP: Using OpenPGP Keys for Transport Layer Security (TLS) Authentication
4309	AES-CCM Mode with IPsec Encapsulating Security Payload (ESP)
5116	An Interface and Algorithms for Authenticated Encryption (AEAD)
3749	TLS Compression Method
3943	TLS Protocol Compression Using Lempel-Ziv-Stac (LZS)
3546	TLS Extensions (obsolete)
4366	TLS Extensions
4868	Using HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512 with IPsec
5116	An Interface and Algorithms for Authenticated Encryption
4749	TLS Compression Methods
5077	TLS session resumption without Server-Side State
5746	TLS Extension: Renegotiation Indication Extension
5764	TLS Extension: SRTP
5929	TLS Extension: Channel Bindings
6066	TLS Extension: Extension Definitions
7301	TLS Extension: Application-Layer Protocol Negotiation (ALPN)
7633	TLS Extension: Feature Extension: Must Staple
6176	Prohibiting Secure Sockets Layer (SSL) Version 2.0
3711	The Secure Real-time Transport Protocol (SRTP)
6189	ZRTP: Media Path Key Agreement for Unicast Secure RTP
6520	TLS Extensions: Heartbeat
6961	TLS Multiple Certificate Status Request Extension
7627	TLS Session Hash and Extended Master Secret Extension
6460	NSA Suite B Profile for TLS
2560	Online Certificate Status Protocol (OCSP, obsolete)
6267	Online Certificate Status Protocol Algorithm Agility (OCSP, obsolete)
4210	X509 PKI Certificate Management Protocol (CMP)
3279	x509 Algorithms and Identifiers for X.509 PKI and CRL Profile
3739	x509 PKI Qualified Certificates Profile; EU Directive 1999/93/EC
3280	X509 PKI Certificate and Certificate Revocation List (CRL) Profile (obsolete)
4158	X509 PKI Certification Path Building
4387	X509 PKI Operational Protocols: Certificate Store Access via HTTP
5280	X509 PKI Certificate and Certificate Revocation List (CRL) Profile
6960	X509 Online Certificate Status Protocol (OCSP)
2712	TLSKRB: Addition of Kerberos Cipher Suites to TLS
3268	TLSAES: Advanced Encryption Standard (AES) Cipher Suites for TLS
4132	Addition of Camellia Cipher Suites to TLS
4162	Addition of SEED Cipher Suites to TLS
4279	TLSPSK: Pre-Shared Key Ciphersuites for TLS
4357	Additional Cryptographic Algorithms for Use with GOST 28147-89, GOST R 34.10-94, GOST R 34.10-2001, and GOST R 34.11-94 Algorithms
4491	Using the GOST Algorithms with X509 (GOST R 34.10-94, GOST R 34.10-2001, GOST R 34.11-94)
4492	TLSECC: Elliptic Curve Cryptography (ECC) Cipher Suites for TLS
4785	Pre-Shared Key (PSK) Cipher Suites with NULL Encryption for TLS
5054	Secure Remote Password (SRP) Protocol for TLS Authentication
5114	Additional Diffie-Hellman Groups for Use with IETF Standards
5288	AES Galois Counter Mode (GCM) Cipher Suites for TLS
5289	TLS Elliptic Curve Cipher Suites with SHA-256/384 and AES Galois Counter Mode (GCM)
5430	Suite B Profile for TLS
5487	Pre-Shared Key Cipher Suites for TLS with SHA-256/384 and AES Galois Counter Mode
5489	ECDHE_PSK Cipher Suites for TLS
5589	Session Initiation Protocol (SIP) Call Control - Transfer
5639	Elliptic Curve Cryptography (ECC) Brainpool Standard Curves and Curve Generation
5903	Elliptic Curve Groups modulo a Prime (ECP Groups) for IKE and IKEv2
7027	Elliptic Curve Cryptography (ECC) Brainpool Curves for TLS
7748	Elliptic Curve for Security
5741	RFC Streams, Headers, and Boilerplates
5794	Description of the ARIA Encryption Algorithm
5932	Camellia Cipher Suites for TLS
6209	Addition of the ARIA Cipher Suites to TLS
6367	Addition of the Camellia Cipher Suites to TLS
6655	AES-CCM Cipher Suites for TLS
7251	AES-CCM Elliptic Curve Cryptography (ECC) Cipher Suites for TLS
7507	TLS Fallback Signaling Cipher Suite Value (SCSV) for Preventing Protocol Downgrade Attacks
5055	Server-Based Certificate Validation Protocol (SCVP)
5019	simplified RFC 2560
5705	Keying Material Exporters for TLS
6125	Representation and Verification of Domain-Based Application Service (PKIX) for TLS
6797	HTTP Strict Transport Security (HSTS)
6962	Certificate Transparency
7366	Encrypt-then-MAC for TLS and DTLS
7457	Summarizing Known Attacks on TLS and DTLS
7469	Public Key Pinning Extension for HTTP
7525	Recommendations for Secure Use of TLS and DTLS
7539	ChaCha20 and Poly1305 for IETF Protocols
7627	TLS Session Hash and Extended Master Secret Extension
7905	ChaCha20-Poly1305 Cipher Suites for TLS
1135	The Helminthiasis of the Internet
6698	DNS-Based Authentication of Named Entities (DANE)
6844	DNS Certification Authority Authorization (CAA) Resource Record

