#!/usr/bin/perl
#?
#? NAME
#?      $0 - install perl moduls
#?
#? DESCRIPTION
#?      Build and install  Net::DNS,  Net::SSLeay  and  IO::Socket::SSL  in a
#?      local private  ./lib  directory.
#?      Using perl instead of sh in the hope that it will be mainly platform-
#?      independent.
#?
#?      In shell-speak it does:
#?          tar xf Net-DNS-x.xx.tar.gz
#?          (cd Net-DNS-x.xx       && perl Makefile.PL && make && make install)
#?          tar xf Net-SSLeay-x.xx.tar.gz
#?          (cd Net-SSLeay-x.xx    && perl Makefile.PL && make && make install)
#?          tar xf IO-Socket-SSL-x.xx.tar.gz
#?          (cd IO-Socket-SSL-x.xx && perl Makefile.PL && make && make install)
#?
#? OPTIONS
#?      --n     - do not execute, just show what would be done
#?      --f     - do not exit if specified  installation  directory exists
#?      --l     - list avaialble modules to be installed
#?
#? LIMITATIONS
#?      Module tarballs must exist in local  ./  directory.
#?      Some perl modules may require  make  and/or  cc  to install properly.
#?      Installation path is hardcoded to  ./lib  to change edit code below.
#?      Unfortunatelly some installations require interactive input.
#?
#? AUTHOR
#?      17-feb-17 Achim Hoffmann
#?
# -----------------------------------------------------------------------------

use strict;
use warnings;
use Cwd;
my  $VERSION  = "@(#) install_perl_modules.pl 1.2 18/10/01 16:38:08";
my  $pwd      = cwd();
my  $lib      = "$pwd";
    $lib      = "$pwd/lib" if ($pwd !~ m#/lib/?#);
my  $try      = "";         # echo for --n
my  $force    = 0 ;         # --f
local $\      = "\n";
my  @modules  = qw(Net-DNS*gz Net-SSLeay*gz IO-Socket-SSL*gz);

# http://search.cpan.org/~nlnetlabs/Net-DNS/
# http://search.cpan.org/CPAN/authors/id/N/NL/NLNETLABS/Net-DNS-1.08.tar.gz
# http://search.cpan.org/CPAN/authors/id/M/MI/MIKEM/Net-SSLeay-1.80.tar.gz
# http://search.cpan.org/CPAN/authors/id/S/SU/SULLR/IO-Socket-SSL-2.047.tar.gz

$try    = "echo" if (grep {/^--?n$/} @ARGV);
$force  = 1      if (grep {/^--?f$/} @ARGV);

if (grep {/^--?l$/} @ARGV) {
    foreach my $module (@modules) {
        my $targz =  (sort glob($module))[-1];
        if (defined $targz) {
            print "# $try $targz -> $lib";
        } else {
            print "# $module\t: not found";
        }
    }
    exit 0;
}

sub do_install {
    my $try   = shift;
    my $tar   = shift;
    my $dst   = shift;
    my $targz =  (sort glob($tar))[-1];
              #  ls Net-SSLeay*gz | sort | tail -1
    chomp $targz;
    my $dir   =  $targz;
       $dir   =~ s/\.tar.gz$//;
       $dir   =~ s/\.tgz$//;    # in case it is .tgz instead of .tar.gz
    my @args  =  (); push(@args, $try) if ($try ne "");
    print "# build $targz ...";
    do {
        push(@args, "tar", "xf", $targz);
        eval { system(@args) }; # TODO: error check
    };
    print "# cd $dir ...";
    chdir($dir) or do {
        warn "**WARNING: cannot cd to '$dir': $!";
        $try = "echo";  # avoids errors in next do{}
    };
    @args  =  (); push(@args, $try) if ($try ne "");
    do {
        # env NO_NETWORK_TESTING=n perl Makefile.PL PREFIX=$lib
        local $ENV{'NO_NETWORK_TESTING'} = "n";
        # eval { require "Makefile.PL", "PREFIX=$lib"; }; # does not work
        @args = ("perl", "Makefile.PL", "PREFIX=$lib");
        eval { system(@args) };
        @args  =  (); push(@args, $try) if ($try ne "");
        push(@args, "make");
        eval { system(@args) };
        push(@args, "install");
        eval { system(@args) };
    };
    return;
}; # do_install

if (-e $lib) {
    if ($force < 1) {
        die "**ERROR: '$lib' exists; please use --f to enforce using it; exit";
    }
} else {
    mkdir($lib);
}

foreach my $module (@modules) {
    print "\n# $try $module -> $lib";
    do_install($try, $module, $lib);
    chdir($pwd);  # not necessary
}
