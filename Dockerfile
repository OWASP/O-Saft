#!/usr/bin/docker build --force-rm --rm -f

#? DESCRIPTION
#?      Dockerfile to build an image with o-saft.tgz using standard openssl.
#?
#? USAGE
#?      This Dockerfile uses "buildargs" variables to build the Docker image.
#?      For default settings, please use:  awk '/^ARG/{print $2}' Dockerfile
#?
#?          OSAFT_VERSION
#?              Version of this build (should be used as image tag also).
#?
#?          OSAFT_VM_FROM
#?              Base image to be used for this build. Tested images are:
#?                  (2017) alpine:3.6  alpine:edge  debian:stretch-slim debian
#?                  (2018) alpine:3.8  debian
#?                  (2019) alpine:3.10 debian:10.2-slim
#?                  (2024) alpine:3.20
#?
#?          OSAFT_VM_USER
#?              Username to be added in the build image.
#?
#?          OSAFT_VM_APT_INSTALL
#?              Additional packages  to be installed in the image.
#?              Note that the package names depend on the used base image.
#?              Default:  tcl  tk  xvfb
#?
#?          OSAFT_VM_SRC_OSAFT
#?              URL to fetch o-saft.tgz archive.
#?
#?          OSAFT_VM_SHA_OSAFT
#?              SHA256 checksum for the o-saft.tgz archive.
#?              Note that the checksum in the Dockerfile provided by this .tgz
#?              archive is wrong (due to hen-egg-problem).
#?              https://github.com/OWASP/O-Saft/blob/master/Dockerfile  is the
#?              most current version and contains proper checksums.
#?
#?          OSAFT_VM_SHA256URL
#?              URL to fetch o-saft.tgz SHA256 checksum from archive.
#?              The checksum returnes by this URL  will be compared to the one
#?              given by  OSAFT_VM_SHA_OSAFT .
#?              Default: https://raw.githubusercontent.com/OWASP/O-Saft/master/o-saft.tgz.sha256"
#?
#?          OSAFT_VM_TAR_OSAFT
#?              Name of archive file for O-Saft (during build).
#?
#?          OSAFT_VM_TRACE
#?              Additional first shell command in Docker's RUN. Can be used to
#?              enable tracing of build process with:
#?                  --build-arg OSAFT_VM_TRACE="set -x"
#?              Default: (empty)
#?
#? ENVIRONMENT VARIABLES
#?      The build image sets environment variables. They are mainly used for
#?      documentation or by other programs to check for the right build.
#?
#?      Following environment variables are set inside the docker image:
#?
#?          osaft_vm_build
#?              Build version of this image, used by o-saft-docker.
#?          OSAFT_DIR
#?              Directory where O-Saft  is installed.
#?          OPENSSL_DIR
#?              Directory where OpenSSL is installed.
#?          OPENSSL_VERSION
#?              Version of installed OpenSSL
#?          TERM
#?              Prefered X-Terminal program.
#?          PATH
#?              PATH for shell, set to:
#?                  ${OSAFT_DIR}:${OSAFT_DIR}/usr:$PATH
#?          WORK_DIR
#?              Directory where to build the packages  (used for  Dockerfile's
#?              WORKDIR  dierective.
#?
#? EXAMPLES
#?      Simple build with defaults:  alpine:edge, o-saft.tgz, openssl-chacha
#?          docker build --force-rm --rm \ 
#?                  -f Dockerfile -t owasp/o-saft .
#?
#?      Simple build with base image alpine:3.8
#?          docker build --force-rm --rm \ 
#?                  --build-arg "OSAFT_VM_FROM=alpine:3.8" \ 
#?                  -f Dockerfile -t owasp/o-saft .
#?
#?      Simple build with base image debian:10.2-slim
#?          docker build --force-rm --rm \ 
#?                  --build-arg "OSAFT_VM_FROM=debian:10.2-slim" \ 
#?                  -f Dockerfile -t owasp/o-saft .
#?
#?      Build with base image alpine:3.6 without Tcl/Tk
#?          docker build --force-rm --rm \ 
#?                  --build-arg "OSAFT_VM_FROM=alpine:3.6" \ 
#?                  --build-arg "OSAFT_VM_APT_INSTALL=" \ 
#?                  -f Dockerfile -t owasp/o-saft .
#?
#?      Build with other SHA256 checksum for o-saft.tgz
#?          docker build --force-rm --rm \ 
#?                  --build-arg "OSAFT_VM_SHA_OSAFT=caffee" \ 
#?                  -f Dockerfile -t owasp/o-saft .
#?
#?      Build with development O-Saft download from github
#?          docker build --force-rm --rm \ 
#?                  --build-arg "OSAFT_VM_SRC_OSAFT=https://github.com/OWASP/O-Saft/archive/master.tar.gz" \ 
#?                  --build-arg "OSAFT_VERSION=latest-development" \ 
#?                  -f Dockerfile -t owasp/o-saft .
#?
#?      Note that  o-saft-docker  searches for a Docker image  owasp/o-saft
#?      so don't forget to tag at least one image with this name.
#?
# HACKER's Info
#       Note that the base package alpine uses busybox as shell. This shell is
#       very picky, in particular for the expr command.
#

ARG     OSAFT_VM_FROM=alpine:3.20

FROM    $OSAFT_VM_FROM
MAINTAINER Achim <achim@owasp.org>

# Parameters passed to build
	# OSAFT_VM_FROM must be defined again, otherwise its value is not available
ARG     OSAFT_VM_FROM
ARG     OSAFT_VM_TRACE
ARG     OSAFT_VM_USER=osaft
ARG     OSAFT_VM_SRC_OSAFT="https://github.com/OWASP/O-Saft/raw/master/o-saft.tgz"
#ARG     OSAFT_VM_SHA_OSAFT="5f23bbed8d411d84faec29c0a5da07ca58a64702c98339c7e7739450f0f9161c"
ARG     OSAFT_VM_SHA_OSAFT="3332af75f20933b4be4dd2e49c8d67cd505fc7856f4844211671e2fd304bbefb"
ARG     OSAFT_VM_SHA256URL="https://raw.githubusercontent.com/OWASP/O-Saft/master/o-saft.tgz.sha256"
ARG     OSAFT_VM_TAR_OSAFT="o-saft.tgz"
ARG     OSAFT_VM_APT_INSTALL="tcl tk xvfb"
ARG     OSAFT_VERSION="24.09.24"
ARG     _SELF_="Dockerfile"
#       _SELF_ for internal use only to make multiple references unique

LABEL \
	VERSION="$OSAFT_VERSION"	\
	\
	DESCRIPTION="Build O-Saft docker image (with openssl 3.x)"	\
	SYNOPSIS="docker build --force-rm --rm -f ./$_SELF_ -t owasp/o-saft:$OSAFT_VERSION -t owasp/o-saft:$OSAFT_VERSION ." \
	DETAILS="Please see https://github.com/OWASP/O-Saft/raw/master/o-saft-docker" \
	SOURCE0="https://github.com/OWASP/O-Saft/raw/master/$_SELF_" \
	SOURCE1="$OSAFT_VM_SRC_OSAFT" \
	SID="@(#) Dockerfile 3.1 24/09/07 22:31:51" \
	AUTHOR="Achim Hoffmann"	

ENV     osaft_vm_build  "$_SELF_ $OSAFT_VERSION; FROM $OSAFT_VM_FROM"
ENV     OSAFT_DIR       /O-Saft
ENV     OPENSSL_DIR     /usr/bin/openssl
ENV     OPENSSL_VERSION 3.3.2
ENV     TERM            xterm
ENV     PATH            ${OSAFT_DIR}:${OSAFT_DIR}/usr:$PATH
ENV     WORK_DIR	/

WORKDIR	$WORK_DIR

RUN \
	$OSAFT_VM_TRACE ; \
	echo "#== Configure user" && \
	if expr "X$OSAFT_VM_FROM" : Xdebian >/dev/null ; then \
	    adduser --quiet --home ${OSAFT_DIR} ${OSAFT_VM_USER} ; \
	    passwd  --delete ${OSAFT_VM_USER} ; \
	else \
	    adduser -D -h ${OSAFT_DIR} ${OSAFT_VM_USER} ; \
	fi && \
	mkdir -p ${OSAFT_DIR}			&& \
	\
	echo "#== Configure apk (alpine) or apt (debian); default: apk" && \
	apt_exe=apk && \
	apt_add=add && \
	opt_add=--no-cache && \
	packages="curl $OSAFT_VM_APT_INSTALL \
		perl perl-readonly openssl \
		perl-io-socket-ssl perl-net-ssleay perl-net-dns perl-net-libidn \
		perl-mozilla-ca ca-certificates" && \
	if expr "X$OSAFT_VM_FROM" : Xdebian >/dev/null ; then \
	   apt_exe=apt-get	; \
	   apt_add=install	; \
	   opt_add=--yes	; \
	   packages="curl perl ca-certificates $OSAFT_VM_APT_INSTALL \
	   	libio-socket-ssl-perl libnet-ssleay-perl libnet-dns-perl libnet-libidn-perl" ; \
	fi && \
	\
	echo "#== Install required packages, development tools and libs" && \
	#apk update && \   # no update needed and not wanted
	if expr "X$OSAFT_VM_FROM" : Xdebian >/dev/null ; then \
	    $apt_exe update ; \
	fi && \
	$apt_exe $apt_add $opt_add $packages	&& \
	\
	echo "#== Workaround for docker/alpine (bug or race condition)" && \
	#   in some alpine versions, resolving a hostname fails, see
	#   https://forums.docker.com/t/resolved-service-name-resolution-broken-on-alpine-and-docker-1-11-1-cs1/19307/23
	#   as workaround we try to prefetch the name resolution;
	#   however, it is not bullet proof either ...
	workaround_alpine_bug() { \
	    expr "X$OSAFT_VM_FROM" : Xdebian >/dev/null && return ; \
	    for host in github.com codeload.github.com cpan.metacpan.org search.cpan.org cpan.metacpan.org ; do \
	        echo -n "#   resolving $host ... " && ping -c 1 $host > /dev/null && echo SUCCESS || echo FAILDED ; \
	    done; } && \
	\
	echo "#== Pull and install O-Saft"	&& \
	workaround_alpine_bug			&& \
	cd    $WORK_DIR				&& \
	curl --insecure --location --silent $OSAFT_VM_SRC_OSAFT -o $OSAFT_VM_TAR_OSAFT	&& \
	# check sha256 if there is one
	[ -n "$OSAFT_VM_SHA_OSAFT" ]		&& \
		sha256=$(command curl --location --silent $OSAFT_VM_SHA256URL |awk '{print $1}') && \
		[ "$sha256" != "$OSAFT_VM_SHA_OSAFT" ]	&& \
			echo "#   WARNING: retrived checksum differs from given checksum for $OSAFT_VM_TAR_OSAFT" && \
			echo "#   WARNING: adapt SAFT_VM_SHA_OSAFT in $_SELF_ or set it empty using --build-arg" && \
			echo "#   $sha256" && \
			echo "#   $OSAFT_VM_SHA_OSAFT" && \
		echo "$OSAFT_VM_SHA_OSAFT  $OSAFT_VM_TAR_OSAFT" | sha256sum -c ; \
		\
	tar   -xzf ${OSAFT_VM_TAR_OSAFT}	&& \
	# handle master directory from github, mv to ${OSAFT_DIR}
	# checks fail sometimes, hence in a sub-shell
	(\
	  [ -d "./O-Saft-master" ] && mv ./O-Saft-master/*           ${OSAFT_DIR}/ ; \
	  [ -d "./O-Saft-master" ] && mv ./O-Saft-master/.[a-zA-Z]*  ${OSAFT_DIR}/ ; \
	  [ -d "./O-Saft-master" ] && rm -rf ./O-Saft-master/ 	; \
	  exit 0 ; \
	) && \
	chown -R root:root   ${OSAFT_DIR}		&& \
	chown -R ${OSAFT_VM_USER}:${OSAFT_VM_USER} ${OSAFT_DIR}/doc	&& \
	chown -R ${OSAFT_VM_USER}:${OSAFT_VM_USER} ${OSAFT_DIR}/lib	&& \
	chown -R ${OSAFT_VM_USER}:${OSAFT_VM_USER} ${OSAFT_DIR}/usr	&& \
	chown    ${OSAFT_VM_USER}:${OSAFT_VM_USER} ${OSAFT_DIR}/.o-saft.pl && \
	chmod 666 ${OSAFT_DIR}/.o-saft.pl		&& \
	\
	echo "#== Cleanup" && \
	rm   -rf  ./t Makefile tags CHANGES README.md Dockerfile* && \
	rm    -f  ${OSAFT_VM_TAR_OSAFT}			&& \
	echo ""

WORKDIR $OSAFT_DIR
USER    $OSAFT_VM_USER
RUN     o-saft-docker usage

ENTRYPOINT ["/O-Saft/o-saft.pl"]
CMD     ["--norc",  "--help=docker"]

# vim:set ft=dockerfile:
