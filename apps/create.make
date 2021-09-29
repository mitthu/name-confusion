# Run as: make -e TEST=f01
SHELL=/bin/bash
TAR_OUTPUT=/tmp/all.tar
ZIP_OUTPUT=/tmp/all.zip
DIFF_OUTPUT=/tmp/all.patch

tar: clean
	@GLOBIGNORE="Makefile"; cd tests/$(TEST); tar -cvf $(TAR_OUTPUT) *

zip: clean
	cd tests/$(TEST); zip -r $(ZIP_OUTPUT) *

diff: clean
	cd tests/; diff -ruN f00 $(TEST) >$(DIFF_OUTPUT) || test $$? -eq 1

clean:
	@rm -f $(TAR_OUTPUT) \
	       $(ZIP_OUTPUT) \
	       $(DIFF_OUTPUT)
	@rm -rf tests/
	@../gentests.sh
