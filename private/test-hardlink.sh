#!/bin/bash
#
# Test case for ncmonitor.sh: hardlink alias
# 
WORKSPACE=linktest

trace_start() {
	sudo rm -f /var/log/audit/*
	rm -f logs.auditd
	sudo service auditd rotate
	sudo auditctl -w /mercury/research/casefolding -k icase
}

trace_end() {
	sudo auditctl -D
	sudo service auditd rotate
	sudo ausearch -k icase | tee logs.auditd >/dev/null
	# sudo rm /var/log/audit/audit.log.1
}

cleanup() {
	rm -rf $WORKSPACE
} 

# Sanity checks
cleanup

# Setup
mkdir $WORKSPACE
pushd $WORKSPACE

trace_start
# Test case
{
	touch regfile
	ln regfile hardlink # create hardlink

	echo "bad write?" >regfile
}

popd
trace_end

# Free up resources
cleanup
