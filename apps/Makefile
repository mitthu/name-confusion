# Run as: make -e TEST=f01 <target>
#
# Example:
#   make -e TEST=f01 tar   # in case-sensitive dir
#   make untar             # in case-insensitive dir
#
# Symlink to this Makefile from case sensitive & an insensitive
# folders. Run the primary command (ex. tar) in sensitive one.
# Run the complemantary command (ex. untar) in insensitive one.

SHELL=/bin/bash
GLOBIGNORE="Makefile:*.make:gentests.sh"
ROOT := $(dir $(shell realpath $(firstword $(MAKEFILE_LIST))))
GENTESTS := $(ROOT)gentests.sh

# Temporary output
TAR_OUTPUT=/tmp/all.tar
ZIP_OUTPUT=/tmp/all.zip
DIFF_OUTPUT=/tmp/all.patch
CP_OUTPUT=/tmp/cp.txt
RSYNC_OUTPUT=/tmp/rsync.txt

all:
	@echo "specify utility to test"

# tar
tar: clean-compress
	cd tests/$(TEST); tar -cvf $(TAR_OUTPUT) *

untar: clean-expand
	-tar -xvf $(TAR_OUTPUT)
	@cat README

# zip/unzip
zip: clean-compress
	cd tests/$(TEST); zip --symlinks -r $(ZIP_OUTPUT) *

unzip: clean-expand
	-unzip $(ZIP_OUTPUT)
	@cat README

# diff/patch
diff: clean-compress
	cd tests/; diff -ruN --no-dereference $(TEST)_patch $(TEST) >$(DIFF_OUTPUT) || test $$? -eq 1

patch: clean-expand
	-patch -s -p1 <$(DIFF_OUTPUT)
	@cat README

# cp -ar src/* dst
cp: clean-compress
	echo `pwd`/tests/$(TEST)/ >$(CP_OUTPUT)

docp: clean-expand
	-cp -ar `cat $(CP_OUTPUT)` .
	@cat `basename $$(cat $(CP_OUTPUT))`/README

# cp -ar src/ dst
cpstar: clean-compress
	echo `pwd`/tests/$(TEST)/\* >$(CP_OUTPUT)

docpstar: clean-expand
	-cp -ar `cat $(CP_OUTPUT)` .
	@cat README

# rsync -avr src/ dst/
rsync: clean-compress
	echo `pwd`/tests/$(TEST)/ >$(RSYNC_OUTPUT)

dorsync: clean-expand
	-rsync -avrH `cat $(RSYNC_OUTPUT)` .
	@cat README

# Clean
clean: clean-compress-basic clean-expand

clean-compress-basic:
	@rm -f $(TAR_OUTPUT) \
	       $(ZIP_OUTPUT) \
	       $(DIFF_OUTPUT)
	@rm -rf tests/

clean-compress: clean-compress-basic
	@$(GENTESTS)

clean-expand:
	@GLOBIGNORE="$(GLOBIGNORE)"; rm -rf *
