
echo "#########################################################################"
echo "# This is just a simple script to get O-Saft running when cloned from git"
echo "#   In general it is not recommended to run the O-Saft tools from within"
echo "#   the installation directory, but to move it into a path found by your"
echo "#   PATH  environment variable."

mkdir release_information_only
mv CHANGES contrib openssl_h-to-perl_hash o-saft-README README o-saft.tgz release_information_only

echo "# consider copying  .o-saft.pl  into your working directory"               
[   -e $HOME/.o-saft.tcl ] && echo "# consider to update your $HOME/.o-saft.tcl  from  contrib/.o-saft.tcl"
[ ! -e $HOME/.o-saft.tcl ] && echo "# consider copying  contrib/.o-saft.tcl  into your HOME directory: $HOME"
echo "#########################################################################"
echo

# finally run some kind of self-check and move myself into release_information_only
o-saft_check_before_install.sh
mv $0 release_information_only

## this shell script does not use a hash-bang line, so it should work anywhere
