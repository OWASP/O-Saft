#!/bin/cat
#?
#? NAME
#?      .o-saft.pl  -  resource file for o-saft.pl
#? DESCRIPTION
#?      Contains arguments and options for o-saft.pl .
#? SYNOPSIS
#?      File must be located in current working directory  or installation
#?      directory of  o-saft.pl .
#? SYNTAX
#?      Empty lines are ignored.
#?      Lines starting with  #  are ignored (comment lines).
#?      Each other line will be passed as one single argument or option.
#?      The string right to the leftmost  =  character is used verbatim.
#?      Note that all values for  --cfg-cmd=  are all lower case letters.
#? NEW COMMANDS
#?      New commands may be defined herein using  --cfg_cmd=  .
#?      Please see example  +preload  below.
#?      New Hints may be defined herein using  --cfg_hint=  .
#?
#?      It is recommended to use a prefix in each private command to avoid
#?      conflicts with existing (or future) commands in o-saft.pl itself.
#?      Following prefixes (for commands) are not used by o-saft.pl:
#?          +fy- +ma- +mein- +mea- +meu- +mi- +mia- +mijn- +min- +mio
#?          +mo- +moj- +mon- +muj- +my- +nire-
#?
#?      The special line
#?         ##? Some text
#?      contains a brief description for following command defined with
#?         --cfg_cmd=my-cmd=...
#?      This description will be used with  --help=commands  option and in
#?      the GUI.
#? VERSION
#?      @(#) .o-saft.pl 1.118 25/07/09 12:53:38
#? AUTHOR
#?      13-dec-13 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

_SID.rc = 1.118; # our own SID required for Makefile and some tools

###
### force to use private openssl
###
#--openssl=/usr/local/openssl/bin/openssl
#--openssl-cnf=/usr/local/openssl/ssl/openssl.cnf
#--force-openssl
### or
#--lib=/usr/local/lib

### disable special openssl options (if not supported by openssl)
#--no-nextproto
#--no-reconnect
#--no-tlsextdebug

###
### specify CA bundle
###
--ca-path=/etc/ssl/certs/
--ca-file=/etc/ssl/certs/ca-certificates.crt
--ca-depth=4

###
### disable cipher checks
###
#--no-tcp
#--no-sslv2
#--no-sslv3
#--no-tlsv1
#--no-tlsv11
#--no-tlsv12
#--no-tlsv13
#--no-udp
#--no-dtlsv1
#--no-dtlsv11
#--no-dtlsv12
#--no-dtlsv13

###
### avoid various problems
###
#--ssl-lazy
#--no-http
#--no-sni
#--no-dns
#--no-md5-cipher
#--no-cert
#--ignorecase

###
### HTTP requests
###
#--http-auth="Basic VVNFUjpQQVNT"
#--http-user=USER
#--http-pass=PASS
#--http-user-agent=o-saft.pl 42.42

###
### make output parsable
###
#--label=owasp
#--showhost
#--trace=key
#--header
#--no-header
#--no-warning
#--separator=CHAR
#--enabled

###
### omit output for commands
###
# commands are used witout + prefix
# Example: all commands for various BSI compliance checks 'cause these checks
# are rarely used in practice and most likely produce a huge amount of data.

--ignore-output=tr_03116+
--ignore-output=tr_03116-
--ignore-output=rfc_7525
--ignore-output=ism
--ignore-output=pci
--ignore-output=fips
--ignore-output=ev+

###
### anonymise strings in output
###
# Pattern for strings to be anonymised in output,  mainly used in CGI mode to
# avoid information disclosure.
# Note that the pattern should contain the internal variable names also.
#--anon_output=(anon_output|anon_text)

###
### define new command +preload
###
##? Check STS header preload attributes
#       To satisfy the requirements on  https://hstspreload.appspot.com/  the
#       HSTS header must:
#         * have the max-age with at least 18 weeks (10886400 seconds)
#         * have the includeSubDomains attribute
#         * have the preload attribute
#         * redirect to https first, then to sub-domains (if redirected)
#         * have an HSTS header in each redirect to https.
#
#       Additionally, the site must have:
#         * a valid certificate
#         * serve all subdomains over https.
#
#       Except the last requirement, following  +preload  will do the checks.
#
--cfg_cmd=preload=sts_maxage18 sts_subdom sts_preload hsts_is301 hsts_samehost hsts_httpequiv expired hsts_maxage hsts_subdom hsts_preload

###
### define new command +ciphercheck
###
##? Check various cipher usage
# +ciphers shows which ciphers are accepted/supported and shows the severity.
# This command summarizes the other cipher checks.
#
--cfg_cmd=ciphercheck=cipher_selected cipher_strong cipher_null cipher_adh cipher_exp cipher_cbc cipher_des cipher_rc4 cipher_edh cipher_pfs cipher_pfsall cnt_ciphers cnt_totals

###
### define new command +names
###
##? Collection of all info and check commands related to certificate names
#
--cfg_cmd=names=cn subject issuer altname verify_altname verify_hostname hostname sni certfqdn wildcard wildhost rfc_2818_names rfc_6125_names

###
### define new command +ocsp
###
##? Collection of all info and check commands related to OCSP data
#
--cfg_cmd=ocsp=ocsp_response ocsp_response_status ocsp_cert_status ocsp_this_update ocsp_next_update ocsp_subject_hash ocsp_public_hash ocsp_uri ocsp_valid ocsp_stapling len_ocsp

--cfg_hint=ocsp=use +oscp_response_data to get the full response

###
### define new command +fingerprints
###
##? Check all certificate fingerprints
# +ciphers shows which ciphers are accepted/supported and shows the severity.
# This command summarizes the other cipher checks.
#
--cfg_cmd=fingerprints=fingerprint_type fingerprint fingerprint_hash fingerprint_md5 fingerprint_sha1 fingerprint_sha2 fp_not_md5

###
### reconfigure list of check for special commands (+http +check ...)
###
# The default behaviour to print the results is to loop over the list of hash
# keys. This is usually a sorted alphanumerically according the key name. For
# human readability, the default behaviour  may not be appropriate. Hence the
# sequence of the output can be sorted as needed. Therefore simply define the
# commands to be used below. They then will be printed in that order.
#
# NOTE that the list defined here overwrites o-saft.pl's default list, which
#      can result in missing output.
#      In particular after updates, the local .o-saft.pl containing redefines
#      should be checked against o-saft.pl's default commands.
# Hint: use --tracekey which prints the keys

###
### redefine command +http
###
##? Redefinition of internal command with fixed instead of sorted order.
--cfg_cmd=http=http_status http_location http_refresh http_sts https_status https_server https_location https_refresh https_content_enc https_transfer_enc https_alerts https_sts hsts_maxage hsts_subdom hsts_preload http_https hsts_is301 hsts_is30x hsts_redirect hsts_samehost hsts_fqdn hsts_httpequiv hsts_sts hsts_location hsts_refresh sts_maxage sts_subdom sts_maxage0d sts_maxage1d sts_maxage1m sts_maxage1y sts_maxage18 sts_maxagexy sts_expired https_pins http

###
### redefine command +hsts
###
##? Redefinition of internal command with fixed instead of sorted order.
--cfg_cmd=hsts=http_https hsts_is301 hsts_is30x hsts_redirect hsts_samehost hsts_fqdn hsts_ip hsts_httpequiv hsts_maxage hsts_preload hsts_subdom hsts_sts hsts_location hsts_refresh sts_maxage sts_subdom sts_maxage0d sts_maxage1d sts_maxage1m sts_maxage1y sts_maxage18 sts_maxagexy sts_expired

###
### redefine command +info
###
##? Redefinition of internal command with fixed instead of sorted order.
--cfg_cmd=info=certversion cn subject subject_hash issuer issuer_hash serial fingerprint fingerprint_type fingerprint_hash fingerprint_sha2 fingerprint_sha1 fingerprint_md5 before after dates email sigdump signame sigkey_len sigkey_value pubkey pubkey_algorithm modulus_len pubkey_value modulus_exponent aux trustout ocspid ocsp_uri ocsp_public_hash ocsp_subject_hash selfsigned chain chain_verify extensions altname verify_altname verify_hostname verify error_verify compression expansion heartbeat master_secret resumption_psk resumption renegotiation srp krb5 psk_identity psk_hint ocsp_response alpns npns alpn npn next_protocols public_key_len dh_parameter master_key session_id session_id_ctx session_ticket session_lifetime session_startdate session_starttime fallback_protocol sslversion http_status http_location http_refresh http_sts https_server https_status https_location https_refresh https_content_enc https_transfer_enc https_alerts https_sts hsts_maxage hsts_subdom hsts_preload http_https hsts_is301 hsts_is30x hsts_redirect hsts_fqdn hsts_httpequiv hsts_sts hsts_location hsts_refresh sts_maxage sts_subdom sts_maxage0d sts_maxage1d sts_maxage1m sts_maxage1y sts_maxage18 sts_maxagexy https_pins info
# useless for +info ('cause aliases): issuer issuer_hash
# included in +info to be printed with --v :
#      certificate sigdump pubkey extensions ext_*
#      ext_* printed with +info--v

###
### redefine command +check
###
##? Redefinition of internal command with fixed instead of sorted order.
--cfg_cmd=check=cipher_selected cipher_strong hassslv2 hassslv3 hastls10 hastls11 hastls12 hastls13 hasdtls12 cipher_null cipher_adh cipher_exp cipher_cbc cipher_des cipher_rc4 cipher_edh cipher_pfs cipher_pfsall dh_512 dh_2048 ecdh_256 ecdh_512 ism pci fips tr_02102+ tr_02102- tr_03116+ tr_03116- rfc_7525 beast breach ccs crime time drown freak heartbleed logjam lucky13 poodle rc4 robot sloth sweet32 sni hostname reversehost cps crl crl_valid dv ev+ ev- ev_chars crnlnull nonprint ocsp_uri ocsp_valid fp_not_md5 sha2signature sig_encryption sig_enc_known pub_encryption pub_enc_known modulus_exp_1 modulus_exp_65537 modulus_exp_oldssl modulus_size_oldssl expired dates rootcert selfsigned constraints verify certfqdn wildcard wildhost rfc_2818_names rfc_6125_names sernumber http_https hsts_is301 hsts_is30x hsts_redirect hsts_samehost hsts_fqdn hsts_ip hsts_httpequiv hsts_sts hsts_location hsts_refresh sts_preload sts_maxage sts_subdom sts_maxage0d sts_maxage1d sts_maxage1m sts_maxage1y sts_maxage18 sts_maxagexy sts_expired https_pins krb5 psk_identity psk_hint session_ticket session_lifetime session_random ocsp_stapling closure sgc zlib open_pgp lzo hasalpn hasnpn fallback master_secret resumption renegotiation srp compression heartbeat sstp scsv cnt_checks_yes cnt_checks_no cnt_checks_noo cnt_ciphers cnt_totals cnt_chaindepth cnt_altname cnt_wildcard len_cps len_crl len_crl_data len_ocsp len_oids len_altname len_chain len_issuer len_pembase64 len_pembinary len_publickey len_sigdump len_subject len_sernumber check
# missing because rarely used: hasdtls1 and hasdtls13
# useless for +check:    ip
# don't use   +check:    cnt_exitcode (for debugging or special purpose only)
# following TBD:         cipher_order, cipher_weak, cps_valid

###
### redefine command +quick
###
##? Redefinition of internal command with fixed instead of sorted order.
--cfg_cmd=quick=sslversion hassslv2 hassslv3 hastls10 hastls11 hastls12 hastls13 hasdtls12 cipher cipher_selected cipher_strong cipher_null cipher_adh cipher_exp cipher_cbc cipher_des cipher_rc4 cipher_edh cipher_pfs beast ccs crime drown freak heartbleed logjam lucky13 poodle rc4 robot sloth sweet32 fingerprint_hash fp_not_md5 sha2signature pub_encryption email serial subject dates verify compression expansion heartbeat hostname hsts_sts crl master_secret resumption renegotiation
# missing because rarely used: hasdtls1 and hasdtls13

###
### redefine command +sizes
###
##? Redefinition of internal command with fixed instead of sorted order.
--cfg_cmd=sizes=cnt_chaindepth cnt_wildcard cnt_altname len_altname len_subject len_issuer len_pembase64 len_pembinary len_publickey len_sigdump len_sernumber len_chain len_cps len_crl len_crl_data len_ocsp len_oids

###
### redefine command +bsi
###
##? Redefinition of internal command with fixed instead of sorted order.
--cfg_cmd=bsi=after dates crl cipher_rc4 renegotiation tr_02102+ tr_02102- tr_03116+ tr_03116-

###
### redefine command +pfs
###
##? Redefinition of internal command with fixed instead of sorted order.
--cfg_cmd=pfs=cipher_pfs cipher_pfsall session_random

###
### redefine command +protocols
###
##? Redefinition of internal command with fixed instead of sorted order.
--cfg_cmd=prots=hassslv2 hassslv3 hastls10 hastls11 hastls12 hastls13 hasdtls1 hasdtls12 hasdtls13 hasalpn hasnpn session_protocol fallback_protocol alpns npns alpn npn next_protocols https_protocols http_protocols https_svc http_svc
# lists all protocols, even the rarely used

###
### redefine command +vulns
###
##? Redefinition of internal command with fixed instead of sorted order.
--cfg_cmd=vulns=beast breach ccs crime drown freak heartbleed logjam lucky13 poodle rc4 robot sloth sweet32 time hassslv2 hassslv3 compression fallback cipher_pfs session_random renegotiation resumption

###
### redefine texts
###
# Syntax
#     --cfg_text=KEY=VALUE
#
# the new (VALUE) string consist of all characters right to left-most =
# all \n, \r and \t will be replace by corresponding character
#
# NOTE that @@ is a placeholder and will be replaced with actual value
# NOTE that charater = will be lost if it is the last character in line
#      workaround: add space or \t
#
# Hint
#     o-saft.pl --help=text     can be used to get all available texts.
#
# Examples below simply set texts to German.
#
#--cfg_text=anon_text= <<verschleiert>>
#--cfg_text=cert_chars= <<nicht erlaubte Zeichen in @@>>
#--cfg_text=cert_dates= <<ungültiges Datum des Zertifikats>>
#--cfg_text=cert_valid= <<Gültigkeitsdauer des Zertifikats zu groß @@>>
#--cfg_text=cipher=Schlüssel
#--cfg_text=desc=Beschreibung
#--cfg_text=desc_check=Prüfergebnis ('yes' ist gut)
#--cfg_text=desc_info=Wert
#--cfg_text=desc_score=Score (max. Wert 100)
#--cfg_text=disabled=<<N/A da @@ benutzt>>
#--cfg_text=disabled_test=<<Test mit/für @@ deaktiviert>>
#--cfg_text=disabled_protocol=<<N/A da Protokoll deaktiviert oder nicht omplementiert>>
#--cfg_text=EV_large= <<@@ zu groß>>
#--cfg_text=EV_subject_CN=<<Werte CN= und commonName sind unterschiedlich>>
#--cfg_text=EV_subject_host=<<Werte CN= und angegebener Hostname sind unterschiedlich>>
#--cfg_text=gethost=<<gethostbyaddr() failed>>
#--cfg_text=host_DNS=DNS Einträge für übergebenen Hostnamen
#--cfg_text=host_IP=IP des übergebenen Hostnamens
#--cfg_text=host_name=Übergebener Hostname
#--cfg_text=host_rhost=Reverse resolved Hostname
#--cfg_text=insecure=<<unsichere(r) @@>>
#--cfg_text=invalid=<<ungültige(r) @@>>
#--cfg_text=miss_ECDSA=<<Schlüssel ECDHE-ECDSA-* fehlt>>
#--cfg_text=miss_RSA=<<Schlüssel ECDHE-RSA-* fehlt>>
#--cfg_text=miss_cipher=<<N/A da kein Schlüssel gefunden>>
#--cfg_text=miss_protocol=<<N/A da kein Protokoll gefunden>>
#--cfg_text=missing=<<@@ fehlt>>
#--cfg_text=na=<<N/A>>
#--cfg_text=need_cipher=<<Prüfung nur in Verbindung mit `+cipher' möglich>>
#--cfg_text=no_cert=<<N/A da --no-cert verwendet>>
#--cfg_text=no_dns=<<N/A da --no-dns verwendet>>
#--cfg_text=no_http=<<N/A da --no-http verwendet>>
#--cfg_text=no_tlsextdebug= <<N/A da --no-tlsextdebug verwendet>>
#--cfg_text=no_reneg=<<secure renegotiation nicht unterstützt>>
#--cfg_text=no_STS=<<N/A da STS nicht gesetzt>>
#--cfg_text=out_checks=\n=== Prüfungen ===
#--cfg_text=out_ciphers=\n=== Schlüssel: prüfe @@ ===
#--cfg_text=out_infos=\n=== Informationen ===
#--cfg_text=out_list==== Liste @@ Schlüssel ====
#--cfg_text=out_scoring=\n=== Bewertung ===
#--cfg_text=out_summary==== Schlüssel: Zusammenfassung @@ ===
#--cfg_text=out_target=\n==== Zielsystem: @@ ====\n
#--cfg_text=protocol=<<Protokoll evt. angeboten, es werden aber keine Schlüssel akzeptiert>>
#--cfg_text=response=<<Antwort>>
#--cfg_text=security=Sicherheit
#--cfg_text=support=angeboten
#--cfg_text=undef=<<undefiniert>>
#--cfg_text=wildcards=<<verwendet Wildcards:@@>>

#
# unknown option, to force warning "option with trailing spaces"
#
#--option=-with_trailing_spaces   

