#!/bin/cat
#?
#? NAME
#?      .o-saft.pl  -  resource file for o-saft.pl
#? DESCRIPTION
#?      Contains arguments and options for o-saft.pl .
#? SYNOPSIS
#?      File must be located in current working directory or installation
#?      directory of  o-saft.pl .
#? SYNTAX
#?      Empty lines are ignored.
#?      Lines starting with  #  are ignored (comment lines).
#?      Each other line will be passed as one single argument or option.
#?

###
### force to use private openssl
###
#--openssl=/usr/local/bin/openssl
#--force-openssl 

###
### disable cipher checks
###
#--no-sslv2
#--no-sslv3

###
### make output parsable
###
#--trace=key
#--no-header
#--enabled

# NOTE all cmd-* commands need to contain the command itself, i.e. http in cmd-http

###
### redefine +http : sorted output
###
--cmd-http=http_301 http_location http_refresh http_status http_sts https_server https_location https_refresh https_status https_alerts hsts hsts_maxage hsts_pins hsts_subdom http_redirect http_fqdn http_https sts_redirect pfs sts sts_location sts_maxage sts_pins sts_refresh sts_subdom sts_maxage0d sts_maxage1d sts_maxage1m sts_maxage1y sts_maxagexy http

###
### redefine +check : sorted output
###
--cmd-check=default cnt_totals order adh export null rc4 edh ism pci fips tr-02102 bsi-tr-02102+ bsi-tr-02102- beast-default beast breach crime time sni hostname reversehost cps crl ev+ ev- ev-chars crnlnull nonprint ocsp certfqdn expired fp_not_md5 rootcert selfsigned valid verify wildcard wildhost http_https sts_redirect http_redirect http_fqdn pfs sts sts_maxage sts_pins sts_subdom sts_refresh sts_location hasSSLv2 krb5 master_key psk_hint psk_identity closure sgc zlib open_pgp lzo fallback renegotiation resumption session_id session_ticket srp sts_maxage0d sts_maxage1m sts_maxage1y sts_maxage1d sts_maxagexy http_301 http_location http_refresh http_status http_sts https_server https_location https_refresh https_status https_alerts hsts hsts_pins hsts_maxage hsts_subdom cnt_altname cnt_chaindepth cnt_ciphers cnt_wildcard len_CPS len_CRL len_CRL_data len_OCSP len_OIDs len_altname len_chain len_issuer len_pembase64 len_pembinary len_publickey len_sigdump len_subject check
# useless for --cmd-check:    ip
# don't use   --cmd-check:   (SSLv|TLSv)*

