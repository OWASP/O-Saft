#!/bin/bash
#
# script provided by HeitorG https://github.com/HeitorG

if [ -e /etc/pacman.conf ]
then
	sudo pacman -S perl --needed
elif [ -e /etc/apt ]
then
	sudo apt-get install perl
elif [ -e /etc/yum.conf ]
then
	sudo yum install perl perl-CPAN
else 
	echo "Your system is unsupported by this script"
	echo "Please install the dependencies manually"
	echo "open the terminal and type: sudo cpan install strict Net::SSLeay IO::Socket::SSL IO::Socket::INET Net::DNS"
fi
sudo cpan install strict Net::SSLeay IO::Socket::SSL IO::Socket::INET Net::DNS

if [ -e /usr/share/O-Saft ]
then
	sudo rm -rf /usr/share/O-Saft
fi

if [ -e /usr/bin/O-Saft ]
then
	sudo rm /usr/bin/O-Saft
fi

cd .. && sudo mv O-Saft /usr/share/

sudo sh -c 'echo "#!/bin/bash" > /usr/bin/O-Saft'
sudo sh -c 'echo "cd /usr/share/O-Saft" >> /usr/bin/O-Saft'
sudo sh -c 'echo "exec perl o-saft.pl $@" >> /usr/bin/O-Saft'
sudo chmod +x /usr/bin/O-Saft
clear
echo "Type 'O-Saft', to open."
