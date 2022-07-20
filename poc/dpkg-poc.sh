#!/bin/bash
set -e
# Script requires: dpkg
#
# Problem:
# Installing a new package may silently replace files that were installed by
# existing packages. This behavior can occur on a case-insensitive file-system.
#
# Description:
# dpkg tracks files that were installed by .deb packages. This information is
# stored inside "/var/lib/dpkg/info/*.list" files. When installing a
# new package, dpkg throws an error if the new package will replace files that
# are part of existing installed packages.
#
# POC:
# Run the script as:
# 	./dpkg-poc.sh <path_to_case_insensitive_directory>
#
# The script creates two packages in /tmp/poc called: myapp1 and myapp2.
# These packages contain a file named "appfile" that will be created in the
# directory passed from the command-line.
#
# Next, the POC script installs "myapp1" and prints the contents of "appfile".
# Then the POC script installs "myapp2" and again print the contents of "appfile".
# The content printed on the console will be different each time because
# they come from different packages. Specifically, the print comes from "myapp1"
# and second print comes from "myapp2".
#
# Tested on: Ubuntu 20.04.4 LTS, dpkg v1.19.7 (amd64)


RED='\033[0;31m'
NC='\033[0m' # No Color

# Install directory
INSTALLDIR=$1

if [[ -z "$INSTALLDIR" ]]; then
	echo -e "${RED}Run as:${NC} $0 <case-insensitive-directory>"
	exit 1
elif [[ ${INSTALLDIR::1} != '/' ]]; then
	echo -e "${RED}Requires absolute path to install directory${NC}"
	exit 1
else
	echo -e "${RED}Using directory:${NC} $INSTALLDIR"
fi

#############################
# POC
#############################
BASE=/tmp/poc

# Sanity checks
rm -rf $BASE
sudo dpkg --remove myapp1
sudo dpkg --remove myapp2

# Create packages
PKGBASE=${INSTALLDIR:1} # remove leading '/'
mkdir -p $BASE/myapp1/DEBIAN "$BASE/myapp1/$PKGBASE"
mkdir -p $BASE/myapp2/DEBIAN "$BASE/myapp2/$PKGBASE"

cat >$BASE/myapp1/DEBIAN/control <<EOF
Package: myapp1
Version: 1.0.0
Architecture: all
Maintainer: Your Name <you@example.com>
Description: My test package, please ignore
EOF
echo "file from myapp1" >"$BASE/myapp1/$PKGBASE/appfile"

cat >$BASE/myapp2/DEBIAN/control <<EOF
Package: myapp2
Version: 1.0.0
Architecture: all
Maintainer: Your Name <you@example.com>
Description: My test package, please ignore
EOF
echo "file from myapp2" >"$BASE/myapp2/$PKGBASE/APPFILE"

# Build packages
(cd $BASE; dpkg -b myapp1/)
(cd $BASE; dpkg -b myapp2/)

# Install packages
sudo dpkg -i $BASE/myapp1.deb
echo -e "${RED}Installed myapp1${NC}"
echo -en "${RED}Contents of ${INSTALLDIR}/appfile: ${NC}"
cat "$INSTALLDIR/appfile"

sudo dpkg -i $BASE/myapp2.deb
echo -e "${RED}Installed myapp2${NC}"
echo -en "${RED}Contents of ${INSTALLDIR}/appfile: ${NC}"
cat "$INSTALLDIR/appfile"

# Cleanup
sudo dpkg --remove myapp1
sudo dpkg --remove myapp2
