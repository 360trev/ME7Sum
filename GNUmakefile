include vars.mk

EXE     =me7sum$(EXE_EXT)
LIBS    =ini
SUBDIRS =inifile
LDFLAGS=-Linifile

include makefile.common

dist: force
	./build.cmd clean
	./build.cmd

INIS=sample.ini bins/ferrari360.ini bins/8D0907551M.ini
.PHONY: zip
zip: dist
	zip -j me7sum-$(GIT_VERSION).zip README $(INIS)
