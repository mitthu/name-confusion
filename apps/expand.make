SHELL:=/bin/bash
TAR_OUTPUT=/tmp/all.tar
ZIP_OUTPUT=/tmp/all.zip
DIFF_OUTPUT=/tmp/all.patch

tar: clean
	@-tar -xvf $(TAR_OUTPUT)
	@cat README

zip: clean
	@-unzip $(ZIP_OUTPUT)
	@cat README

patch: clean
	@-patch -su -p0 <$(DIFF_OUTPUT)
	@cat README

clean:
	@GLOBIGNORE="Makefile"; rm -rf *
